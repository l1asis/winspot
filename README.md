# winspot

winspot is a Python utility and command-line tool to export, reset, and download Windows Spotlight images.
Additionally, it can download Bing's daily images.

## Installation

Install directly from PyPI using [pip](https://pip.pypa.io/en/stable/) or [pipx](https://pipx.pypa.io/stable/):

```bash
pip install winspot
# or
pipx install winspot
```

Or install the latest version from source:

```bash
git clone https://github.com/l1asis/winspot.git
cd winspot
pip install .
```

## Usage

### CLI

winspot uses subcommands to organize different operations:

#### Extract Windows Spotlight

```bash
# Save all wallpapers (cached, desktop, lockscreen)
winspot extract

# Save only cached wallpapers
winspot extract --cached

# Save only desktop wallpaper
winspot extract --desktop

# Save only lock screen wallpaper
winspot extract --lockscreen

# Save only landscape wallpapers with duplicate prevention
winspot extract --orientation landscape --prevent-duplicates
```

#### Download Bing Daily Images

```bash
# Download today's Bing image in 4K
winspot bing

# Download the last 7 days of images
winspot bing --count 7

# Download in 1080p with specific locale
winspot bing --resolution 1920x1080 --locale de-DE
```

#### Reset Windows Spotlight

```bash
# Reset with confirmation prompt
winspot --reset

# Force reset without confirmation
winspot --reset --force
```

For complete help:

```bash
winspot --help
winspot extract --help
winspot bing --help
```

### As a Library

```python
import winspot

# Save with default settings (all sources)
winspot.extract_wallpapers()

# Save only cached wallpapers
winspot.extract_wallpapers(desktop=False, lockscreen=False)

# Save only landscape wallpapers with duplicate prevention
winspot.extract_wallpapers(
    orientation="landscape",
    prevent_duplicates=True
)

# Save with conflict resolution
winspot.extract_wallpapers(
    on_conflict="skip",  # or "overwrite", "rename"
)

# Download Bing daily images
winspot.download_bing_daily_images(
    count=7,
    resolution="3840x2160",
    locale="en-US",
    prevent_duplicates=True
)

# Reset Windows Spotlight settings
winspot.reset_windows_spotlight()
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## Acknowledgments

* Thanks to Paulo Scardine for the `get_image_size.py` script used in this project.

## License

Distributed under the MIT License. See [`LICENSE`](https://github.com/l1asis/winspot/blob/main/LICENSE) for more information.
