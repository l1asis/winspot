import argparse
import ctypes
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from types import TracebackType
from typing import TYPE_CHECKING, Literal

try:
    import requests

    requests_imported = True
except ImportError:
    requests_imported = False
    if TYPE_CHECKING:
        import requests

from . import __about__, __version__, logger
from .logger_config import setup_logging
from .vendor.get_image_size import try_get_image_size


# ============================================================================
# STRUCTURES
# ============================================================================
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self):
        return "{%08X-%04X-%04X-%s-%s}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            "".join(["%02X" % b for b in self.Data4[:2]]),
            "".join(["%02X" % b for b in self.Data4[2:]]),
        )


class PROPERTYKEY(ctypes.Structure):
    _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]


class PROPVARIANT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [
            ("lVal", ctypes.c_long),
            ("pwszVal", ctypes.c_wchar_p),  # For strings
            # Add other types here if needed (e.g., filetime, bool)
        ]

    _anonymous_ = ("u",)
    _fields_ = [
        ("vt", ctypes.c_ushort),
        ("wReserved1", ctypes.c_ushort),
        ("wReserved2", ctypes.c_ushort),
        ("wReserved3", ctypes.c_ushort),
        ("u", _U),
    ]


class IPropertyStore(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(ctypes.c_void_p))]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.CHAR * wintypes.MAX_PATH),
    ]


# ============================================================================
# DLL LOADING & HELPER FUNCTIONS
# ============================================================================
_ole32 = ctypes.windll.ole32
_shell32 = ctypes.windll.shell32
_kernel32 = ctypes.windll.kernel32
_advapi32 = ctypes.windll.advapi32


def DEFINE_PROPERTYKEY(guid_str: str, pid: int) -> PROPERTYKEY:
    """
    Parses a GUID string and PID into a cached PROPERTYKEY structure.
    """
    pkey = PROPERTYKEY()
    pkey.pid = pid
    # Convert string to GUID struct immediately
    _ole32.CLSIDFromString(guid_str, ctypes.byref(pkey.fmtid))
    return pkey


# ============================================================================
# FUNCTION PROTOTYPES
# ============================================================================
# HRESULT CLSIDFromString([in] LPOLESTR lpsz, [out] LPCLSID pclsid);
_ole32.CLSIDFromString.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(GUID)]
_ole32.CLSIDFromString.restype = ctypes.c_long

# HRESULT SHGetPropertyStoreFromParsingName([in] PCWSTR pszPath, [in] IBindCtx *pbc, [in] DWORD flags, [in] REFIID riid, [out] void **ppv);
_shell32.SHGetPropertyStoreFromParsingName.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.POINTER(IPropertyStore)),
]
_shell32.SHGetPropertyStoreFromParsingName.restype = ctypes.c_long

# HANDLE GetCurrentProcess()
_kernel32.GetCurrentProcess.argtypes = []
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE

# BOOL OpenProcessToken([in] HANDLE ProcessHandle, [in] DWORD DesiredAccess, [out] PHANDLE TokenHandle)
_advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
_advapi32.OpenProcessToken.restype = wintypes.BOOL

# BOOL GetTokenInformation([in] HANDLE TokenHandle, [in] TOKEN_INFORMATION_CLASS TokenInformationClass, [out] LPVOID TokenInformation, [in] DWORD TokenInformationLength, [out] PDWORD ReturnLength)
_advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_advapi32.GetTokenInformation.restype = wintypes.BOOL

# BOOL ConvertSidToStringSidA([in] PSID Sid, [out] LPSTR *StringSid)
_advapi32.ConvertSidToStringSidA.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_char_p),
]
_advapi32.ConvertSidToStringSidA.restype = wintypes.BOOL

# BOOL CloseHandle([in] HANDLE hObject)
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL

# HANDLE CreateToolhelp32Snapshot([in] DWORD dwFlags, [in] DWORD th32ProcessID)
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

# BOOL Process32First([in] HANDLE hSnapshot, [out] LPPROCESSENTRY32 lppe)
_kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_kernel32.Process32First.restype = wintypes.BOOL

# BOOL Process32Next([in] HANDLE hSnapshot, [out] LPPROCESSENTRY32 lppe)
_kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_kernel32.Process32Next.restype = wintypes.BOOL

# HRESULT CoInitialize([in, optional] LPVOID pvReserved)
_ole32.CoInitialize.argtypes = [ctypes.c_void_p]
_ole32.CoInitialize.restype = ctypes.c_long

# VOID CoUninitialize()
_ole32.CoUninitialize.argtypes = []
_ole32.CoUninitialize.restype = None

FnSetValue = ctypes.WINFUNCTYPE(
    ctypes.HRESULT,
    ctypes.c_void_p,
    ctypes.POINTER(PROPERTYKEY),
    ctypes.POINTER(PROPVARIANT),
)
FnCommit = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p)
FnRelease = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)

# ============================================================================
# CONSTANTS
# ============================================================================
GPS_READWRITE = 0x00000002
VT_LPWSTR = 31
VT_EMPTY = 0
TH32CS_SNAPPROCESS = 0x00000002
TOKEN_QUERY = 0x0008
TOKEN_USER = 1

IID_IPropertyStore = GUID(
    0x886D8EEB,
    0x8CF2,
    0x4446,
    (ctypes.c_ubyte * 8)(0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99),
)

PKEY_Title = DEFINE_PROPERTYKEY("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 2)
PKEY_Subject = DEFINE_PROPERTYKEY("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 3)
PKEY_Author = DEFINE_PROPERTYKEY("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 4)
PKEY_Comment = DEFINE_PROPERTYKEY("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 6)
PKEY_Copyright = DEFINE_PROPERTYKEY("{64440492-4C8B-11D1-8B70-080036B11A03}", 11)

# ============================================================================
# END OF SETUP
# ============================================================================


class WindowsMetadataEditor:
    """Context manager for editing Windows file metadata."""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self.store = None
        self.initialized_com = False

    def __enter__(self):
        hr = _ole32.CoInitialize(None)
        if hr == 0 or hr == 1:
            self.initialized_com = True
        elif hr == -2147417850 or hr == 0x80010106:
            pass
        else:
            raise OSError(f"Failed to initialize COM library: {hex(hr & 0xFFFFFFFF)}")

        self.store = ctypes.POINTER(IPropertyStore)()
        hr = _shell32.SHGetPropertyStoreFromParsingName(
            self.file_path,
            None,
            GPS_READWRITE,
            ctypes.byref(IID_IPropertyStore),
            ctypes.byref(self.store),
        )
        if hr != 0:
            if self.initialized_com:
                _ole32.CoUninitialize()
                self.initialized_com = False
            raise OSError(f"Failed to open file: {hex(hr & 0xFFFFFFFF)}")
        return self

    def set_property(self, pkey: PROPERTYKEY, value: str) -> None:
        if not self.store:
            raise OSError("Property store is not initialized.")

        vtable = self.store.contents.lpVtbl

        SetValueFunc = FnSetValue(vtable[6])

        propvar = PROPVARIANT()
        if not value:
            propvar.vt = VT_EMPTY
        else:
            propvar.vt = VT_LPWSTR
        propvar.pwszVal = value

        hr = SetValueFunc(self.store, ctypes.byref(pkey), ctypes.byref(propvar))

        if hr != 0:
            raise OSError(f"Failed to set property: {hex(hr & 0xFFFFFFFF)}")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.store:
            vtable = self.store.contents.lpVtbl

            if exc_type is None:
                CommitFunc = FnCommit(vtable[7])
                CommitFunc(self.store)

            ReleaseFunc = FnRelease(vtable[2])
            ReleaseFunc(self.store)
            self.store = None

        if self.initialized_com:
            _ole32.CoUninitialize()
            self.initialized_com = False


def _get_user_confirmation(prompt: str, is_strict: bool = False) -> bool:
    """Prompts the user for a yes/no confirmation."""

    valid_yes = {"y", "yes", "yeah", "yep"}
    valid_no = {"n", "no", "nah", "nope"}

    suffix = "(y/n)" if is_strict else "(y/N)"

    while True:
        response = input(f"{prompt} {suffix}: ").strip().lower()

        if response in valid_yes:
            return True
        elif response in valid_no:
            return False
        elif not is_strict:
            return False

        print(f"Invalid input '{response}'. Please enter 'y' or 'n'.")


def _add_image_metadata(
    path: str,
    title: str | None = None,
    subject: str | None = None,
    copyright: str | None = None,
    comment: str | None = None,
    author: str | None = None,
) -> None:
    """Adds metadata to an image file on Windows."""

    try:
        with WindowsMetadataEditor(path) as editor:
            if title is not None:
                editor.set_property(PKEY_Title, title)
            if subject is not None:
                editor.set_property(PKEY_Subject, subject)
            if copyright is not None:
                editor.set_property(PKEY_Copyright, copyright)
            if comment is not None:
                editor.set_property(PKEY_Comment, comment)
            if author is not None:
                editor.set_property(PKEY_Author, author)
    except Exception:
        pass


def _get_pid_by_name(process_name: str) -> int | None:
    """Retrieves the PID of a process by its name."""

    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return None

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not _kernel32.Process32First(snapshot, ctypes.byref(entry)):
        _kernel32.CloseHandle(snapshot)
        return None

    pid = None
    while True:
        if entry.szExeFile.decode().lower() == process_name.lower():
            pid = entry.th32ProcessID
            break
        if not _kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break

    _kernel32.CloseHandle(snapshot)
    return pid


def _get_user_sid() -> str | None:
    """Retrieves the current user's SID as a string."""

    process_handle = _kernel32.GetCurrentProcess()
    token_handle = wintypes.HANDLE()

    if not _advapi32.OpenProcessToken(
        process_handle, TOKEN_QUERY, ctypes.byref(token_handle)
    ):
        return None

    # Determine required buffer size
    return_length = wintypes.DWORD()
    _advapi32.GetTokenInformation(
        token_handle, TOKEN_USER, None, 0, ctypes.byref(return_length)
    )

    # Fetch the actual token information
    buffer = ctypes.create_string_buffer(return_length.value)
    if _advapi32.GetTokenInformation(
        token_handle,
        TOKEN_USER,
        buffer,
        return_length.value,
        ctypes.byref(return_length),
    ):
        # The SID is a pointer within the structure; convert it to a string
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        string_sid = ctypes.c_char_p()
        _advapi32.ConvertSidToStringSidA(sid_pointer, ctypes.byref(string_sid))
        if string_sid.value:
            _kernel32.CloseHandle(token_handle)
            return string_sid.value.decode()

    _kernel32.CloseHandle(token_handle)
    return None


def _clear_directory(path: str) -> None:
    """Deletes all files and subdirectories in the specified directory."""
    logger.debug("Clearing directory: %s", path)
    for entry in os.scandir(path):
        try:
            if entry.is_file() or entry.is_symlink():
                os.unlink(entry.path)
            elif entry.is_dir():
                shutil.rmtree(entry.path)
        except Exception:
            logger.error("Failed to delete %s", entry.path, exc_info=True)


def _hash_file_sha256(path: str, chunk_size: int = 65536) -> str:
    if hasattr(hashlib, "file_digest"):
        with open(path, "rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
    else:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()


def _smart_copy(
    source_path: str,
    output_path: str,
    on_conflict: Literal["rename", "overwrite", "skip"] = "rename",
    prevent_duplicates: bool = False,
) -> bool:
    """
    Copies a file with smart conflict resolution
    and optional duplicate prevention based on file content.

    :param source_path: Path to the source file.
    :type source_path: str
    :param output_path: Path to the destination file.
    :type output_path: str
    :param on_conflict: Conflict resolution strategy when the destination file exists.
    :type on_conflict: Literal["rename", "overwrite", "skip"]
    :param prevent_duplicates: If True, prevents copying if a file with identical content already exists in the output directory.
    :type prevent_duplicates: bool
    :return: True if the file was copied, False otherwise.
    :rtype: bool
    """

    if not os.path.exists(source_path):
        return False

    source_size = os.path.getsize(source_path)
    source_hash = None
    output_dir = os.path.dirname(output_path) or "."

    if prevent_duplicates and os.path.exists(output_dir):
        for entry in os.scandir(output_dir):
            if entry.is_file() and entry.stat().st_size == source_size:
                if source_hash is None:
                    source_hash = _hash_file_sha256(source_path)
                if _hash_file_sha256(entry.path) == source_hash:
                    return False  # Content exists (anywhere), skip.

    if os.path.exists(output_path):
        if on_conflict == "skip":
            return False
        elif on_conflict == "overwrite":
            pass
        elif on_conflict == "rename":
            base, extension = os.path.splitext(output_path)
            counter = 1
            while os.path.exists(output_path):
                # Optimization: Only rename if content is actually DIFFERENT.
                # If file.txt exists and is identical, we shouldn't make file (1).txt
                if os.path.getsize(output_path) == source_size:
                    if source_hash is None:
                        source_hash = _hash_file_sha256(source_path)
                    if _hash_file_sha256(output_path) == source_hash:
                        return False  # Skip, don't create a numbered duplicate
                output_path = f"{base} ({counter}){extension}"
                counter += 1

    os.makedirs(output_dir, exist_ok=True)
    shutil.copy2(source_path, output_path)
    logger.debug(
        "Copied: %s -> %s", os.path.basename(source_path), os.path.basename(output_path)
    )
    return True


def reset_windows_spotlight() -> None:
    """Resets Windows Spotlight to try to fetch new images."""
    logger.info("Starting Windows Spotlight reset...")

    # Terminate SystemSettings to unlock files
    pid = _get_pid_by_name("SystemSettings.exe")
    if pid is not None:
        logger.debug("Terminating SystemSettings.exe (PID: %d)", pid)
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)  # Give it a moment to terminate

    user_profile_path = os.getenv("USERPROFILE")
    if not user_profile_path:
        user_profile_path = "C:\\Users\\Default"

    settings_path = f"{user_profile_path}\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\Settings"
    themes_path = f"{user_profile_path}\\AppData\\Roaming\\Microsoft\\Windows\\Themes"

    if os.path.exists(settings_path) and os.path.isdir(settings_path):
        logger.debug("Clearing Spotlight settings")
        _clear_directory(settings_path)
    else:
        logger.warning("Spotlight settings directory not found: %s", settings_path)

    transcoded_wallpaper_path = os.path.join(themes_path, "TranscodedWallpaper")
    if os.path.exists(transcoded_wallpaper_path) and os.path.isfile(
        transcoded_wallpaper_path
    ):
        logger.debug("Removing TranscodedWallpaper")
        os.remove(transcoded_wallpaper_path)

    # Re-register the Spotlight package via PowerShell
    logger.debug("Re-registering ContentDeliveryManager package")
    try:
        subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Unrestricted",
                "-Command",
                (
                    r"Get-AppxPackage -allusers Microsoft.Windows.ContentDeliveryManager | "
                    r'Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}'
                ),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        logger.warning("Failed to re-register ContentDeliveryManager", exc_info=True)

    # Restart the Explorer process
    pid = _get_pid_by_name("explorer.exe")
    if pid is not None:
        logger.debug("Restarting Explorer")
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)  # Give it a moment to terminate

    subprocess.Popen(["explorer.exe"])
    logger.info("Windows Spotlight reset completed")


def download_bing_daily_images(
    index: int = 0,
    count: int = 1,
    resolution: Literal["1920x1080", "3840x2160", "1080x1920"] | str = "3840x2160",
    locale: str = "en-US",
    on_conflict: Literal["rename", "overwrite", "skip"] = "rename",
    prevent_duplicates: bool = False,
    output_dir: str = ".\\BingDailyImages",
    clear_output: bool = False,
    add_metadata: bool = True,
) -> None:
    """Downloads Bing daily images."""
    logger.info("Starting Bing daily image download to: %s", output_dir)
    logger.debug(
        "Options: index=%d, count=%d, resolution=%s, locale=%s",
        index,
        count,
        resolution,
        locale,
    )

    if not requests_imported:
        logger.error("requests library not installed - cannot download images")
        return

    download_count = 0

    # Pattern: "Description (© Author/Agency)" or "Description (© Author - Agency)"
    # Captures: 1=description, 2=full copyright with ©, 3=photographer name only
    pattern = r"^(.*?) \((©\s*(?:photo by\s+)?([^/\-–—]+?)(?:\s*[/\-–—].*)?)\)$"

    api_endpoint = "https://www.bing.com/HPImageArchive.aspx"
    params = {
        "format": "js",
        "idx": str(index if index >= 0 else 0),
        "n": str(count if 1 <= count <= 8 else min(max(count, 1), 8)),
        "mkt": locale,
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    width, height = resolution.split("x")
    if resolution != "1920x1080":
        params["uhd"] = "1"
        params["uhdwidth"] = width
        params["uhdheight"] = height

    response = requests.get(api_endpoint, params=params, headers=headers)

    if response.status_code != 200:
        logger.error("Failed to fetch Bing daily images: HTTP %d", response.status_code)
    else:
        data = response.json()
        if "images" not in data:
            logger.error("No images found in Bing API response")
        else:
            os.makedirs(output_dir, exist_ok=True)
            if clear_output:
                logger.info("Clearing output directory")
                _clear_directory(output_dir)

            for image in data["images"]:
                image_url = f"https://www.bing.com{image['url']}"
                image_title = image.get("title", "")
                raw_copyright = image.get("copyright", "")

                match = re.search(pattern, raw_copyright)
                if match:
                    image_location = match.group(1).strip()
                    image_copyright = match.group(2).strip()
                    image_author = _normalize_author_separators(match.group(3).strip())
                else:
                    image_location = ""
                    image_copyright = raw_copyright
                    image_author = ""

                metadata_title = image_location or image_title
                metadata_subject = image_title if image_location else None

                image_topic = (
                    image["urlbase"].split(".")[-1].split("_")[0].replace("OHR.", "")
                )
                file_name = (
                    f"Bing_{image['startdate']}_{image_topic}_{width}x{height}.jpg"
                )
                output_path = os.path.join(output_dir, file_name)

                if _download_and_save_image(
                    image_url,
                    output_path,
                    on_conflict,
                    prevent_duplicates,
                    title=metadata_title,
                    subject=metadata_subject,
                    copyright_text=image_copyright,
                    comment=raw_copyright,
                    author=image_author,
                    add_metadata=add_metadata,
                ):
                    download_count += 1

    logger.info("Bing download completed: %d images", download_count)


def _normalize_author_separators(author: str) -> str:
    """Normalizes author separators to semicolons for Windows metadata.

    Converts various separator patterns to semicolons:
    - "A, B, and C" -> "A; B; C"
    - "A and B" -> "A; B"
    - "A, B" -> "A; B"
    """
    if not author:
        return author
    result = re.sub(r",?\s+and\s+", "; ", author, flags=re.IGNORECASE)
    result = re.sub(r",\s*", "; ", result)
    return result


def _download_and_save_image(
    url: str,
    output_path: str,
    on_conflict: Literal["rename", "overwrite", "skip"],
    prevent_duplicates: bool,
    title: str | None = None,
    subject: str | None = None,
    copyright_text: str | None = None,
    comment: str | None = None,
    author: str | None = None,
    add_metadata: bool = True,
) -> bool:
    """Downloads an image from URL and saves it with metadata."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        temp_path = os.path.splitext(output_path)[0] + ".tmp.jpg"
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(temp_path, "wb") as f:
            f.write(response.content)

        if add_metadata:
            _add_image_metadata(
                temp_path,
                title=title,
                subject=subject,
                copyright=copyright_text,
                comment=comment,
                author=author,
            )

        success = _smart_copy(
            temp_path,
            output_path,
            on_conflict=on_conflict,
            prevent_duplicates=prevent_duplicates,
        )

        if os.path.exists(temp_path):
            os.remove(temp_path)

        if success:
            logger.debug("Downloaded: %s", os.path.basename(output_path))

        return success

    except requests.RequestException as e:
        logger.error("Failed to download %s: %s", url, e)
        return False


def download_images(
    api_version: Literal["v3", "v4", "auto", "both"] = "auto",
    country_code: str | None = None,
    locale: str | None = None,
    orientation: Literal["landscape", "portrait", "both"] = "both",
    on_conflict: Literal["rename", "overwrite", "skip"] = "rename",
    prevent_duplicates: bool = False,
    output_dir: str = ".\\WindowsSpotlightImages",
    clear_output: bool = False,
    add_metadata: bool = True,
) -> None:
    """Downloads images from Windows Spotlight API."""
    logger.info("Starting Spotlight API download to: %s", output_dir)
    logger.debug(
        "Options: api_version=%s, country_code=%s, locale=%s, orientation=%s",
        api_version,
        country_code,
        locale,
        orientation,
    )

    if not requests_imported:
        logger.error("requests library not installed - cannot download images")
        return

    if clear_output and os.path.exists(output_dir):
        _clear_directory(output_dir)

    os.makedirs(output_dir, exist_ok=True)

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    iso_utc_now = utc_now.strftime("%Y-%m-%dT%H:%M:%SZ")
    download_count = 0
    v4_success = False

    if api_version in ("v4", "auto", "both"):
        parameters = {
            "fmt": "json",
            "placement": "88000820",
            "bcnt": "4",
            "country": country_code or "US",
            "locale": locale or "en-US",
        }

        try:
            response = requests.get(
                "https://fd.api.iris.microsoft.com/v4/api/selection",
                params=parameters,
                timeout=30,
            )

            if response.ok:
                v4_success = True
                items: list[dict[str, str]] = (
                    response.json().get("batchrsp", {}).get("items", [])
                )

                for raw_item in items:
                    item = json.loads(raw_item.get("item", r"{}"))
                    ad = item.get("ad", {})

                    hover_text = ad.get("iconHoverText", "")
                    location_title = None
                    if hover_text_lines := hover_text.split("\r\n"):
                        location_title = hover_text_lines[0].strip()

                    title = ad.get("title")
                    description = ad.get("description")
                    copyright_text = ad.get("copyright")

                    # Use location as title, API title as subject
                    metadata_title = location_title or title
                    metadata_subject = title if location_title else None
                    metadata_comment = description

                    author = None
                    if copyright_text:
                        match = re.match(
                            r"©\s*(?:photo by\s+)?([^/\-–—]+)",
                            copyright_text,
                            re.IGNORECASE,
                        )
                        if match:
                            author = _normalize_author_separators(
                                match.group(1).strip()
                            )

                    if orientation in ("landscape", "both"):
                        landscape_url = ad.get("landscapeImage", {}).get("asset")
                        if landscape_url:
                            filename = os.path.basename(landscape_url.split("?")[0])
                            output_path = os.path.join(output_dir, filename)

                            if _download_and_save_image(
                                landscape_url,
                                output_path,
                                on_conflict,
                                prevent_duplicates,
                                title=metadata_title,
                                subject=metadata_subject,
                                copyright_text=copyright_text,
                                comment=metadata_comment,
                                author=author,
                                add_metadata=add_metadata,
                            ):
                                download_count += 1

                    if orientation in ("portrait", "both"):
                        portrait_url = ad.get("portraitImage", {}).get("asset")
                        if portrait_url:
                            filename = os.path.basename(portrait_url.split("?")[0])
                            output_path = os.path.join(output_dir, filename)

                            if _download_and_save_image(
                                portrait_url,
                                output_path,
                                on_conflict,
                                prevent_duplicates,
                                title=metadata_title,
                                subject=metadata_subject,
                                copyright_text=copyright_text,
                                comment=metadata_comment,
                                author=author,
                                add_metadata=add_metadata,
                            ):
                                download_count += 1

                logger.info("V4 API: Downloaded %d images", download_count)

        except requests.RequestException as e:
            logger.warning("V4 API request failed: %s", e)
            v4_success = False

    if api_version in ("v3", "both") or (api_version == "auto" and not v4_success):
        parameters = {
            "fmt": "json",
            "pid": "338387",
            "ua": "WindowsShellClient/10.0.19041.1",
            "cdm": "1",
            "pl": locale or "en-US",
            "lc": locale or "en-US",
            "ctry": country_code or "US",
            "time": iso_utc_now,
        }

        try:
            response = requests.get(
                "https://arc.msn.com/v3/Delivery/Placement",
                params=parameters,
                timeout=30,
            )

            if response.ok:
                items = response.json().get("batchrsp", {}).get("items", [])
                v3_count = 0

                for raw_item in items:
                    item = json.loads(raw_item.get("item", r"{}"))
                    ad = item.get("ad", {})

                    title = ad.get("title_text", {}).get("tx")
                    copyright_text = ad.get("copyright_text", {}).get("tx")

                    hs1_text = ad.get("hs1_title_text", {}).get("tx", "")
                    hs2_text = ad.get("hs2_title_text", {}).get("tx", "")
                    description = hs1_text or hs2_text

                    author = None
                    if copyright_text:
                        match = re.match(
                            r"©\s*(?:photo by\s+)?([^/\-–—]+)",
                            copyright_text,
                            re.IGNORECASE,
                        )
                        if match:
                            author = _normalize_author_separators(
                                match.group(1).strip()
                            )

                    if orientation in ("landscape", "both"):
                        landscape_data = ad.get("image_fullscreen_001_landscape", {})
                        landscape_url = landscape_data.get("u")

                        if landscape_url:
                            # Skip empty/placeholder images (fileSize ~736 bytes)
                            file_size = int(landscape_data.get("fileSize", "0"))
                            if file_size > 1000:
                                filename = os.path.basename(landscape_url.split("?")[0])
                                output_path = os.path.join(output_dir, filename)

                                if _download_and_save_image(
                                    landscape_url,
                                    output_path,
                                    on_conflict,
                                    prevent_duplicates,
                                    title=title,
                                    subject=None,
                                    copyright_text=copyright_text,
                                    comment=description,
                                    author=author,
                                    add_metadata=add_metadata,
                                ):
                                    v3_count += 1

                    if orientation in ("portrait", "both"):
                        portrait_data = ad.get("image_fullscreen_001_portrait", {})
                        portrait_url = portrait_data.get("u")

                        if portrait_url:
                            file_size = int(portrait_data.get("fileSize", "0"))
                            if file_size > 1000:
                                filename = os.path.basename(portrait_url.split("?")[0])
                                output_path = os.path.join(output_dir, filename)

                                if _download_and_save_image(
                                    portrait_url,
                                    output_path,
                                    on_conflict,
                                    prevent_duplicates,
                                    title=title,
                                    subject=None,
                                    copyright_text=copyright_text,
                                    comment=description,
                                    author=author,
                                    add_metadata=add_metadata,
                                ):
                                    v3_count += 1

                download_count += v3_count
                logger.info("V3 API: Downloaded %d images", v3_count)

        except requests.RequestException as e:
            logger.error("V3 API request failed: %s", e)

    logger.info("Total downloaded: %d images to %s", download_count, output_dir)
    return


def extract_images(
    cached: bool = True,
    desktop: bool = True,
    lockscreen: bool = True,
    orientation: Literal["landscape", "portrait", "both"] = "both",
    on_conflict: Literal["rename", "overwrite", "skip"] = "rename",
    prevent_duplicates: bool = False,
    output_dir: str = ".\\WindowsSpotlightImages",
    clear_output: bool = False,
) -> None:
    """Extracts Windows Spotlight images based on the specified options."""
    logger.info("Starting image extraction to: %s", output_dir)
    logger.debug(
        "Options: cached=%s, desktop=%s, lockscreen=%s, orientation=%s",
        cached,
        desktop,
        lockscreen,
        orientation,
    )

    app_data = os.getenv("APPDATA")
    local_app_data = os.getenv("LOCALAPPDATA")
    if not app_data or not local_app_data:
        logger.error("Required environment variables APPDATA or LOCALAPPDATA not set")
        return

    assets_path = f"{local_app_data}\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\Assets"
    iris_service_path = f"{local_app_data}\\Packages\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\LocalCache\\Microsoft\\IrisService"
    desktop_path = f"{app_data}\\Microsoft\\Windows\\Themes\\TranscodedWallpaper"
    lockscreen_path = None
    if lockscreen and (user_sid := _get_user_sid()):
        lockscreen_path = (
            f"C:\\ProgramData\\Microsoft\\Windows\\SystemData\\{user_sid}\\ReadOnly"
        )
        if not os.access(lockscreen_path, os.R_OK):
            logger.warning(
                "Lock screen path not accessible (may require admin privileges)"
            )
            lockscreen_path = None

    os.makedirs(output_dir, exist_ok=True)
    if clear_output:
        logger.info("Clearing output directory")
        _clear_directory(output_dir)

    extract_count = 0

    if desktop and os.path.exists(desktop_path) and os.path.isfile(desktop_path):
        logger.debug("Extracting desktop image")
        if _smart_copy(
            desktop_path,
            os.path.join(output_dir, "Desktop.jpg"),
            on_conflict,
            prevent_duplicates,
        ):
            extract_count += 1

    if cached:
        logger.debug("Scanning cached image sources")
        if os.path.exists(iris_service_path) and os.path.isdir(iris_service_path):
            for dirpath, _, filenames in os.walk(iris_service_path):
                for filename in filenames:
                    if filename.lower().endswith((".jpg", ".jpeg")):
                        source_file = os.path.join(dirpath, filename)
                        output_file = os.path.join(output_dir, filename)
                        if os.path.isfile(source_file):
                            if orientation != "both":
                                size = try_get_image_size(source_file)
                                if size is None:
                                    continue
                                w, h = size
                                is_landscape = w >= h
                                if (orientation == "landscape" and is_landscape) or (
                                    orientation == "portrait" and not is_landscape
                                ):
                                    if _smart_copy(
                                        source_file,
                                        output_file,
                                        on_conflict,
                                        prevent_duplicates,
                                    ):
                                        extract_count += 1
                            else:
                                if _smart_copy(
                                    source_file,
                                    output_file,
                                    on_conflict,
                                    prevent_duplicates,
                                ):
                                    extract_count += 1

        if os.path.exists(assets_path) and os.path.isdir(assets_path):
            for entry in os.scandir(assets_path):
                if entry.is_file():
                    source_file = entry.path
                    output_file = os.path.join(output_dir, f"{entry.name}.jpg")
                    if orientation != "both":
                        size = try_get_image_size(source_file)
                        if size is None:
                            continue
                        w, h = size
                        is_landscape = w >= h
                        if (orientation == "landscape" and is_landscape) or (
                            orientation == "portrait" and not is_landscape
                        ):
                            if _smart_copy(
                                source_file,
                                output_file,
                                on_conflict,
                                prevent_duplicates,
                            ):
                                extract_count += 1
                    else:
                        if _smart_copy(
                            source_file,
                            output_file,
                            on_conflict,
                            prevent_duplicates,
                        ):
                            extract_count += 1

    if lockscreen and lockscreen_path:
        logger.debug("Extracting lock screen images")
        if os.path.exists(lockscreen_path) and os.path.isdir(lockscreen_path):
            for entry_name in os.listdir(lockscreen_path):
                if entry_name.lower().startswith("lockscreen"):
                    for filename in os.listdir(
                        os.path.join(lockscreen_path, entry_name)
                    ):
                        source_file = os.path.join(
                            lockscreen_path, entry_name, filename
                        )
                        if os.path.isfile(source_file):
                            output_file = os.path.join(output_dir, filename)
                            if _smart_copy(
                                source_file,
                                output_file,
                                on_conflict,
                                prevent_duplicates,
                            ):
                                extract_count += 1

    logger.info("Extraction completed: %d images", extract_count)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Extract, download, and manage Windows Spotlight images."
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Extract command
    extract_parser = subparsers.add_parser(
        "extract", help="Extract Windows Spotlight images"
    )
    extract_parser.add_argument(
        "-c",
        "--cached",
        action="store_true",
        help="Extract cached images from IrisService and Assets folders",
    )
    extract_parser.add_argument(
        "-d", "--desktop", action="store_true", help="Extract current desktop image"
    )
    extract_parser.add_argument(
        "-l",
        "--lockscreen",
        action="store_true",
        help="Extract current lock screen image (if accessible)",
    )
    extract_parser.add_argument(
        "-r",
        "--orientation",
        type=str,
        default="both",
        choices=["landscape", "portrait", "both"],
        help="Filter images by orientation",
    )

    # Bing daily images command
    bing_parser = subparsers.add_parser("bing", help="Download Bing daily images")
    bing_parser.add_argument(
        "-i", "--index", type=int, default=0, help="Starting index (0 = today)"
    )
    bing_parser.add_argument(
        "-n", "--count", type=int, default=1, help="Number of images to download (1-8)"
    )
    bing_parser.add_argument(
        "-R",
        "--resolution",
        type=str,
        default="3840x2160",
        choices=["1920x1080", "3840x2160", "1080x1920"],
        help="Image resolution",
    )
    bing_parser.add_argument(
        "-L",
        "--locale",
        type=str,
        default="en-US",
        help="Market locale (e.g., en-US, zh-CN)",
    )

    # Download images command
    download_parser = subparsers.add_parser(
        "download", help="Download images from Windows Spotlight API"
    )
    download_parser.add_argument(
        "-a",
        "--api-version",
        type=str,
        default="auto",
        choices=["v3", "v4", "both", "auto"],
        help="API version to use (both queries V4 and V3)",
    )
    download_parser.add_argument(
        "-C", "--country-code", type=str, help="Country code (e.g., US, CN)"
    )
    download_parser.add_argument(
        "-L", "--locale", type=str, help="Locale (e.g., en-US, zh-CN)"
    )
    download_parser.add_argument(
        "-r",
        "--orientation",
        type=str,
        default="both",
        choices=["landscape", "portrait", "both"],
        help="Filter images by orientation",
    )

    # Shared arguments for all commands
    for subparser in [extract_parser, bing_parser, download_parser]:
        subparser.add_argument(
            "-s",
            "--on-conflict",
            type=str,
            default="rename",
            choices=["rename", "overwrite", "skip"],
            help="Action to take when a file with the same name exists",
        )
        subparser.add_argument(
            "-S",
            "--prevent-duplicates",
            action="store_true",
            help="Prevent saving duplicate images based on content",
        )
        subparser.add_argument(
            "-o",
            "--out",
            type=str,
            help="Output directory",
        )
        subparser.add_argument(
            "--clear",
            action="store_true",
            help="Clear the output directory before operation",
        )

    # Shared arguments for download commands only
    for subparser in [bing_parser, download_parser]:
        subparser.add_argument(
            "--no-metadata",
            action="store_true",
            help="Skip adding metadata to downloaded images",
        )

    # Global arguments
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset Windows Spotlight settings to fetch new images",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force reset without confirmation (use with --reset)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output for debugging",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress all output",
    )
    parser.add_argument(
        "--version",
        action="version",
        help="Show program's version number and exit",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--about",
        action="store_true",
        help="Show information about this program",
    )

    args = parser.parse_args(argv)

    if args.about:
        print(__about__)
        return 0

    setup_logging(args.verbose, args.quiet, args.silent)
    logger.info(f"winspot version {__version__} starting...")

    if args.reset:
        if args.force or _get_user_confirmation(
            "This will reset Windows Spotlight settings. Continue?",
            is_strict=False,
        ):
            reset_windows_spotlight()
        else:
            logger.info("Reset cancelled by user")
        return 0

    # Handle commands
    if args.command == "bing":
        download_bing_daily_images(
            index=args.index,
            count=args.count,
            resolution=args.resolution,
            locale=args.locale,
            on_conflict=args.on_conflict,
            prevent_duplicates=args.prevent_duplicates,
            output_dir=args.out or ".\\BingDailyImages",
            clear_output=args.clear,
            add_metadata=not args.no_metadata,
        )
    elif args.command == "download":
        download_images(
            api_version=args.api_version,
            country_code=args.country_code,
            locale=args.locale,
            orientation=args.orientation,
            on_conflict=args.on_conflict,
            prevent_duplicates=args.prevent_duplicates,
            output_dir=args.out or ".\\WindowsSpotlightImages",
            clear_output=args.clear,
            add_metadata=not args.no_metadata,
        )
    elif args.command == "extract":
        if not args.cached and not args.desktop and not args.lockscreen:
            args.cached = True
            args.desktop = True
            args.lockscreen = True

        extract_images(
            cached=args.cached,
            desktop=args.desktop,
            lockscreen=args.lockscreen,
            orientation=args.orientation,
            on_conflict=args.on_conflict,
            prevent_duplicates=args.prevent_duplicates,
            output_dir=args.out or ".\\WindowsSpotlightImages",
            clear_output=args.clear,
        )
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
