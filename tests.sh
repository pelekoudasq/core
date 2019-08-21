#!/bin/bash

pytest tests/ --cov
python3 tests/modprime/vote_signing.py
