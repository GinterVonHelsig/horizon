# Comms-01 GPU installation

The Debian guest initially exposed only `main`, so `contrib`, `non-free`, and
`non-free-firmware` were enabled in the guest's apt sources. Installed:

- NVIDIA Debian driver 550.163.01 and `nvidia-smi`;
- matching cloud-kernel headers and DKMS module;
- qemu-guest-agent;
- git, tmux, htop, nvtop, jq, rsync, build tools and Python development tools;
- isolated `/home/debian/preset-worker-venv`;
- PyTorch 2.6.0 with CUDA 12.4 wheels;
- numpy, pandas, pyarrow, polars, duckdb, optuna, SQLAlchemy, psycopg2,
  Pydantic, FastAPI, Uvicorn, HTTPX, Rich, Typer, joblib, scikit-learn,
  CuPy CUDA 12, and Numba.

The first DKMS attempt targeted the generic kernel while the guest ran the
cloud kernel. Matching cloud headers were installed, DKMS was rebuilt, and
the GPU now passes `nvidia-smi` and PyTorch CUDA checks.
