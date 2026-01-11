import argparse
import ctypes
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from typing import Literal

from . import __about__, __version__, logger
from .vendor.get_image_size import try_get_image_size
from .logger_config import setup_logging


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


def _get_pid_by_name(process_name: str) -> int | None:
    """Retrieves the PID of a process by its name."""

    # Define constants
    TH32CS_SNAPPROCESS = 0x00000002

    # Define structures
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

    # Load necessary Windows libraries
    kernel32 = ctypes.windll.kernel32

    # Define function prototypes
    # HANDLE CreateToolhelp32Snapshot([in] DWORD dwFlags, [in] DWORD th32ProcessID)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    # BOOL Process32First([in] HANDLE hSnapshot, [out] LPPROCESSENTRY32 lppe)
    kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32First.restype = wintypes.BOOL

    # BOOL Process32Next([in] HANDLE hSnapshot, [out] LPPROCESSENTRY32 lppe)
    kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32Next.restype = wintypes.BOOL

    # HANDLE CloseHandle([in] HANDLE hObject)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # Create snapshot of all processes
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return None

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        kernel32.CloseHandle(snapshot)
        return None

    pid = None
    while True:
        if entry.szExeFile.decode().lower() == process_name.lower():
            pid = entry.th32ProcessID
            break
        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break

    kernel32.CloseHandle(snapshot)
    return pid


def _get_user_sid() -> str | None:
    """Retrieves the current user's SID as a string."""

    # Define constants
    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1

    # Load necessary Windows libraries
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    # Define function prototypes
    # HANDLE GetCurrentProcess()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []

    # BOOL OpenProcessToken([in] HANDLE ProcessHandle, [in] DWORD DesiredAccess, [out] PHANDLE TokenHandle)
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL

    # BOOL GetTokenInformation([in] HANDLE TokenHandle, [in] TOKEN_INFORMATION_CLASS TokenInformationClass, [out] LPVOID TokenInformation, [in] DWORD TokenInformationLength, [out] PDWORD ReturnLength)
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL

    # BOOL ConvertSidToStringSidA([in] PSID Sid, [out] LPSTR *StringSid)
    advapi32.ConvertSidToStringSidA.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
    advapi32.ConvertSidToStringSidA.restype = wintypes.BOOL

    # BOOL CloseHandle([in] HANDLE hObject)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # Get current process token
    process_handle = kernel32.GetCurrentProcess()
    token_handle = wintypes.HANDLE()

    if not advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token_handle)):
        return None

    # Determine required buffer size
    return_length = wintypes.DWORD()
    advapi32.GetTokenInformation(token_handle, TOKEN_USER, None, 0, ctypes.byref(return_length))

    # Fetch the actual token information
    buffer = ctypes.create_string_buffer(return_length.value)
    if advapi32.GetTokenInformation(token_handle, TOKEN_USER, buffer, return_length.value, ctypes.byref(return_length)):
        # The SID is a pointer within the structure; convert it to a string
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        string_sid = ctypes.c_char_p()
        advapi32.ConvertSidToStringSidA(sid_pointer, ctypes.byref(string_sid))
        if string_sid.value:
            # Close the token handle
            kernel32.CloseHandle(token_handle)
            return string_sid.value.decode()

    # Close the token handle
    kernel32.CloseHandle(token_handle)
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
    logger.debug("Copied: %s -> %s", os.path.basename(source_path), os.path.basename(output_path))
    return True


def reset_windows_spotlight() -> None:
    """Resets Windows Spotlight to try to fetch new wallpapers."""
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
    if os.path.exists(transcoded_wallpaper_path) and os.path.isfile(transcoded_wallpaper_path):
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


def extract_wallpapers(
    cached: bool = True,
    desktop: bool = True,
    lockscreen: bool = True,
    orientation: Literal["landscape", "portrait", "both"] = "both",
    on_conflict: Literal["rename", "overwrite", "skip"] = "rename",
    prevent_duplicates: bool = False,
    output_dir: str = ".\\WindowsSpotlightWallpapers",
    clear_output: bool = False,
) -> None:
    """Extracts Windows Spotlight wallpapers based on the specified options."""
    logger.info("Starting wallpaper extraction to: %s", output_dir)
    logger.debug(
        "Options: cached=%s, desktop=%s, lockscreen=%s, orientation=%s",
        cached, desktop, lockscreen, orientation
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
        lockscreen_path = f"C:\\ProgramData\\Microsoft\\Windows\\SystemData\\{user_sid}\\ReadOnly"
        if not os.access(lockscreen_path, os.R_OK):
            logger.warning("Lock screen path not accessible (may require admin privileges)")
            lockscreen_path = None

    os.makedirs(output_dir, exist_ok=True)
    if clear_output:
        logger.info("Clearing output directory")
        _clear_directory(output_dir)

    if desktop and os.path.exists(desktop_path) and os.path.isfile(desktop_path):
        logger.debug("Extracting desktop wallpaper")
        _smart_copy(
            desktop_path,
            os.path.join(output_dir, "Desktop.jpg"),
            on_conflict,
            prevent_duplicates,
        )

    if cached:
        logger.debug("Scanning cached wallpaper sources")
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
                                    _smart_copy(
                                        source_file,
                                        output_file,
                                        on_conflict,
                                        prevent_duplicates,
                                    )
                            else:
                                _smart_copy(
                                    source_file,
                                    output_file,
                                    on_conflict,
                                    prevent_duplicates,
                                )

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
                            _smart_copy(
                                source_file,
                                output_file,
                                on_conflict,
                                prevent_duplicates,
                            )
                    else:
                        _smart_copy(
                            source_file,
                            output_file,
                            on_conflict,
                            prevent_duplicates,
                        )

    if lockscreen and lockscreen_path:
        logger.debug("Extracting lock screen wallpapers")
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
                            output_file = os.path.join(
                                output_dir, filename
                            )
                            _smart_copy(
                                source_file,
                                output_file,
                                on_conflict,
                                prevent_duplicates,
                            )

    logger.info("Wallpaper extraction completed")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Extract Windows Spotlight wallpapers."
    )
    parser.add_argument(
        "-c",
        "--cached",
        action="store_true",
        help="Extract cached wallpapers from IrisService and Assets folders",
    )
    parser.add_argument(
        "-d", "--desktop", action="store_true", help="Extract current desktop wallpaper"
    )
    parser.add_argument(
        "-l",
        "--lockscreen",
        action="store_true",
        help="Extract current lock screen wallpaper (if accessible)",
    )
    parser.add_argument(
        "-r",
        "--orientation",
        type=str,
        default="both",
        choices=["landscape", "portrait", "both"],
        help="Filter wallpapers by orientation",
    )
    parser.add_argument(
        "-s",
        "--on-conflict",
        type=str,
        default="rename",
        choices=["rename", "overwrite", "skip"],
        help="Action to take when a file with the same name exists in the output directory",
    )
    parser.add_argument(
        "-S",
        "--prevent-duplicates",
        action="store_true",
        help="Prevent saving duplicate images based on content",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        default=".\\WindowsSpotlightWallpapers",
        help="Output directory for extracted wallpapers",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the output directory before extraction",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset Windows Spotlight settings to fetch new wallpapers",
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
        help="Suppress all output (overrides --verbose and --quiet)",
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
            "This will reset Windows Spotlight settings "
            "and may require admin privileges. Continue?",
            is_strict=False,
        ):
            reset_windows_spotlight()
        else:
            logger.info("Reset cancelled by user")
    else:
        if not args.cached and not args.desktop and not args.lockscreen:
            args.cached = True
            args.desktop = True
            args.lockscreen = True

        extract_wallpapers(
            cached=args.cached,
            desktop=args.desktop,
            lockscreen=args.lockscreen,
            orientation=args.orientation,
            on_conflict=args.on_conflict,
            prevent_duplicates=args.prevent_duplicates,
            output_dir=args.out,
            clear_output=args.clear,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
