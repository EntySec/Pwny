# Monhorn

Monhorn is an implementation of simple ransomware written in pure C and supposed to work with Pwny.

## Usage

Load `monhorn` plugin to the Pwny to add commands.

`load monhorn`

## Implementing

To implement `monhorn` to Pwny follow these steps:

* **1.** Build `monhorn` via make all and move it to `pwny/libs/<platform>/<arch>/`.
* **2.** Move `monhorn.py` to `pwny/plugins/<platform>/`.
