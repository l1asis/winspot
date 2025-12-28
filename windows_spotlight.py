import os
import shutil


def bump_windows_spotlight(destination: str = ".\\WindowsSpotlightWallpapers") -> None:
    user_profile_path = os.getenv("USERPROFILE")
    if not user_profile_path:
        user_profile_path = "C:\\Users\\Default"

    transcoded_wallpaper_path = user_profile_path + "\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\TranscodedWallpaper"
    assets_path = user_profile_path + "\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\Assets"
    
    os.makedirs(destination, exist_ok=True)

    if os.path.exists(transcoded_wallpaper_path) and os.path.isfile(transcoded_wallpaper_path):
        shutil.copy2(transcoded_wallpaper_path, os.path.join(destination, "TranscodedWallpaper.jpg"))

    if os.path.exists(assets_path) and os.path.isdir(assets_path):
        for filename in os.listdir(assets_path):
            source_file = os.path.join(assets_path, filename)
            if os.path.isfile(source_file):
                destination_file = os.path.join(destination, f"{filename}.jpg")
                shutil.copy2(source_file, destination_file)
        
if __name__ == "__main__":
    bump_windows_spotlight()
