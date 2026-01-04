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

from . import __about__, __version__
from .get_image_size import try_get_image_size


def get_user_confirmation(prompt: str, is_strict: bool = False) -> bool:
    """Prompts the user for a yes/no confirmation."""
    if is_strict:
        while True:
            response = input(f"{prompt} (y/n): ").strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no"):
                return False
            else:
                print("Please enter 'y' or 'n'.")
    else:
        response = input(f"{prompt} (y/n): ").strip().lower()
        if response in ("y", "yes"):
            return True
        else:
            return False


def get_pid_by_name(process_name: str) -> int | None:
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


def get_user_sid() -> str | None:
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


def clear_directory(directory_path: str) -> None:
    """Deletes all files and subdirectories in the specified directory."""
    for entry in os.scandir(directory_path):
        try:
            if entry.is_file() or entry.is_symlink():
                os.unlink(entry.path)
            elif entry.is_dir():
                shutil.rmtree(entry.path)
        except Exception as e:
            print(f"Failed to delete {entry.path}. Reason: {e}")


def next_available_filename(file_path: str) -> str:
    """Generates the next available filename by appending a number if necessary."""
    base, extension = os.path.splitext(file_path)
    counter = 1
    while os.path.exists(file_path):
        file_path = f"{base} ({counter}){extension}"
        counter += 1
    return file_path


def _conditional_copy_unique(
    source_file: str,
    output_file: str,
    skip_existing: bool,
) -> None:
    """
    Copies the source file to the output file,
    skipping existing files based on content hash.
    """
    if skip_existing:
        output_file, is_unique = next_available_filename_check_hash(output_file)
        if is_unique:
            shutil.copy2(source_file, output_file)
    else:
        output_file = next_available_filename(output_file)
        shutil.copy2(source_file, output_file)


def next_available_filename_check_hash(file_path: str) -> tuple[str, bool]:
    """
    Generates the next available filename by appending a number if necessary,
    and checks if the file content is identical to an existing file.

    :param file_path: Path to the file to check.
    :type file_path: str
    :return: A tuple containing the next available filename and a boolean indicating
             whether the file content is unique.
    :rtype: tuple[str, bool]
    """
    if not os.path.exists(file_path):
        return file_path, True

    with open(file_path, "rb") as f:
        existing_file_hash = hashlib.file_digest(f, "sha256").hexdigest()

    base, extension = os.path.splitext(file_path)
    counter = 1
    while True:
        new_file_path = f"{base} ({counter}){extension}"
        if not os.path.exists(new_file_path):
            return new_file_path, True
        with open(new_file_path, "rb") as f:
            new_file_hash = hashlib.file_digest(f, "sha256").hexdigest()
        if new_file_hash == existing_file_hash:
            return new_file_path, False
        counter += 1


def reset_windows_spotlight() -> None:
    """Resets Windows Spotlight to try to fetch new wallpapers."""

    # Terminate SystemSettings to unlock files
    pid = get_pid_by_name("SystemSettings.exe")
    if pid is not None:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)  # Give it a moment to terminate

    user_profile_path = os.getenv("USERPROFILE")
    if not user_profile_path:
        user_profile_path = "C:\\Users\\Default"

    settings_path = f"{user_profile_path}\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\Settings"
    themes_path = f"{user_profile_path}\\AppData\\Roaming\\Microsoft\\Windows\\Themes"

    if os.path.exists(settings_path) and os.path.isdir(settings_path):
        clear_directory(settings_path)

    transcoded_wallpaper_path = os.path.join(themes_path, "TranscodedWallpaper")
    if os.path.exists(transcoded_wallpaper_path) and os.path.isfile(transcoded_wallpaper_path):
        os.remove(transcoded_wallpaper_path)

    # Re-register the Spotlight package via PowerShell
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
        pass

    # Restart the Explorer process
    pid = get_pid_by_name("explorer.exe")
    if pid is not None:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)  # Give it a moment to terminate

    subprocess.Popen(["explorer.exe"])


def dump_windows_spotlight(
    extract_assets: bool = True,
    extract_desktop: bool = True,
    extract_lockscreen: bool = True,
    orientation: Literal["landscape", "portrait", "both"] = "both",
    skip_existing: bool = False,
    output_directory: str = ".\\WindowsSpotlightWallpapers",
    clean_output_directory: bool = False,
) -> None:
    """Extracts Windows Spotlight wallpapers to the specified output directory."""
    user_profile_path = os.getenv("USERPROFILE")
    if not user_profile_path:
        user_profile_path = "C:\\Users\\Default"

    desktop_path = f"{user_profile_path}\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper"
    assets_path = f"{user_profile_path}\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\Assets"
    lockscreen_path = None
    if extract_lockscreen and (user_sid := get_user_sid()):
        lockscreen_path = f"C:\\ProgramData\\Microsoft\\Windows\\SystemData\\{user_sid}\\ReadOnly"
        if os.access(lockscreen_path, os.R_OK):
            lockscreen_path = None

    os.makedirs(output_directory, exist_ok=True)
    if clean_output_directory:
        clear_directory(output_directory)

    if extract_desktop and os.path.exists(desktop_path) and os.path.isfile(desktop_path):
        path_to_check = os.path.join(output_directory, "TranscodedWallpaper.jpg")
        _conditional_copy_unique(
            desktop_path,
            path_to_check,
            skip_existing,
        )

    if extract_assets and os.path.exists(assets_path) and os.path.isdir(assets_path):
        for filename in os.listdir(assets_path):
            source_file = os.path.join(assets_path, filename)
            if os.path.isfile(source_file):
                output_file = os.path.join(output_directory, f"{filename}.jpg")

                if orientation != "both":
                    size = try_get_image_size(output_file)
                    if size is None:
                        continue
                    w, h = size
                    is_landscape = w >= h
                    if (orientation == "landscape" and is_landscape) or (
                        orientation == "portrait" and not is_landscape
                    ):
                        _conditional_copy_unique(
                            source_file,
                            output_file,
                            skip_existing,
                        )
                else:
                    _conditional_copy_unique(
                        source_file,
                        output_file,
                        skip_existing,
                    )

    if extract_lockscreen and lockscreen_path and os.path.exists(lockscreen_path) and os.path.isdir(lockscreen_path):
        for name in os.listdir(lockscreen_path):
            if name.lower().startswith("lockscreen"):
                for filename in os.listdir(os.path.join(lockscreen_path, name)):
                    source_file = os.path.join(lockscreen_path, name, filename)
                    if os.path.isfile(source_file):
                        output_file = os.path.join(output_directory, f"LockScreen_{filename}.jpg")
                        _conditional_copy_unique(
                            source_file,
                            output_file,
                            skip_existing,
                        )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Extract Windows Spotlight wallpapers."
    )
    parser.add_argument(
        "-a",
        "--assets",
        action="store_true",
        help="Extract cached wallpapers from Assets folder",
    )
    parser.add_argument(
        "-d", "--desktop", action="store_true", help="Extract current desktop wallpaper"
    )
    parser.add_argument(
        "-l",
        "--lockscreen",
        action="store_true",
        help="Extract current lock screen wallpaper (Requires admin privileges or ownership)",
    )
    parser.add_argument(
        "-r",
        "--orientation",
        type=str,
        default="both",
        choices=["landscape", "portrait", "both"],
        help="Filter wallpapers by orientation (Only for Assets wallpapers)",
    )
    parser.add_argument(
        "-s",
        "--skip-existing",
        action="store_true",
        help="Skip existing files based on content hash (Only if consecutive name conflicts occur)",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=str,
        default=".\\WindowsSpotlightWallpapers",
        help="Destination directory for extracted wallpapers",
    )
    parser.add_argument(
        "-c",
        "--clean",
        action="store_true",
        help="Clean the destination directory before extraction",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
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

    if not args.assets and not args.desktop and not args.lockscreen:
        args.assets = True
        args.desktop = True
        args.lockscreen = True

    dump_windows_spotlight(
        extract_assets=args.assets,
        extract_desktop=args.desktop,
        extract_lockscreen=args.lockscreen,
        orientation=args.orientation,
        skip_existing=args.skip_existing,
        output_directory=args.out,
        clean_output_directory=args.clean,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
