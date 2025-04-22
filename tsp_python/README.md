# tsp_python

A TSP Python API that binds to Rust

## How to run

Using [uv](https://docs.astral.sh/uv/) (this will automatically install the needed packages):
```
uv run test.py
```
Use `--reinstall` to force a reinstall of the packages (in case changes were made). 

Alternatively, you can use `pyenv` with manually installed `maturin` (run within the `tsp_python` directory):
```
pyenv init - | source
pyenv activate 
maturin develop
python3 test.py
```
