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

## Supported targets

There are two types of Pwny.

* **`inmemory`** - Pwny holds encoded host and port in memory as `char data[64]`. In this type the only way to set encoded host and port is to patch Pwny executable and replace `:data:string:` with your encoded host and port.
* **`inline`** - Pwny takes encoded host and port from command line argument. This type makes Pwny executable to show encoded host and port in utilities such as `ps` or `top`, because all data placed in command line argument.

* **macOS** - `make all platform=macos sdk=<path> type=<type>`
* **Apple iOS** - `make all platform=apple_ios sdk=<path> type=<type>`
* **Linux** - `make all platform=linux type=<type>`

**NOTE:** To compile for target `macos` you will need to download patched SDKs from [here](https://github.com/phracker/MacOSX-SDKs) and to compile for `apple_ios` target you will need to download patched SDKs from [here](https://github.com/theos/sdks).

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny import Pwny
from pwny import PwnySession
```

* `Pwny` - Pwny utilities, mostly for generating payloads and encoding arguments.
* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload.

To get Pwny template, you should call `get_template()`.

```python3
from pwny import Pwny

pwny = Pwny()
template = pwny.get_template('linux', 'x64')
```

To encode Pwny data (`host` and/or `port`) use `encode_data()`.

```python3
from pwny import Pwny

pwny = Pwny()
args = pwny.encode_data(host='127.0.0.1', port=8888)
```

There are two types of Pwny - `reverse_tcp` and `bind_tcp`. To use `bind_tcp` instead of `reverse_tcp`, you should encode only `port` in `encode_data()`.

```python3
from pwny import Pwny

pwny = Pwny()
args = pwny.encode_data(port=8888)
```

## Adding Pwny payload

To add Pwny payload to HatSploit you should follow these steps.

* Write a basic HatSploit payload template.
* Import `Pwny` and `PwnySession` and put `Pwny` to `HatSploitPayload` class.
* Set payload parameter `Session` to `PwnySession`.
* Encode data `host` and/or `port` through `encode_data()` and create offset `{'data': encoded_data}`.
* Return `get_template()` with these offset as a payload return value.

In `get_template()` you should put your payload platform and architecture.

```python3
return self.get_template(self.details['Platform'], self.details['Architecture']),
       {'data': encoded_data}
```
