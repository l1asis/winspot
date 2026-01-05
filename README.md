# winspot

winspot is a Python utility and command-line tool to export and reset Windows Spotlight images.

## Installation

> [!WARNING]
> The project was not uploaded to PyPI yet. The installation instructions below assume that it will be available in the future.

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

Run the tool to automatically save Spotlight images:

```bash
winspot
```

For more options (like output directory):

```bash
winspot --help
```

### As a Library

```python
import winspot

# Default: Save everything (cached, desktop, lockscreen)
winspot.extract_wallpapers()

# Save only cached wallpapers
winspot.extract_wallpapers(desktop=False, lockscreen=False)

# Save only desktop wallpapers
winspot.extract_wallpapers(cached=False, lockscreen=False)

# Try to save only lockscreen
winspot.extract_wallpapers(cached=False, desktop=False)

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