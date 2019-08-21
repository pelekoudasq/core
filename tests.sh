#!/bin/bash

pytest tests/ #--cov
# ./tests/run_sessions.sh
python3 tests/modprime/vote_signing.py
