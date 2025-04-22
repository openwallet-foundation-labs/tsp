# tsp_python

A TSP Python API that binds to Rust

## How to run

Use [uv](https://docs.astral.sh/uv/) (uv will automatically install and build the needed packages):
```
uv run test.py
```

Alternatively, you can use `pyenv` with manually installed `maturin` (run within the `tsp_python` directory):
```
pyenv init - | source
pyenv activate 
maturin develop
python3 test.py
```
