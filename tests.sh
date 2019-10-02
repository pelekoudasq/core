#!/bin/bash

pytest crypto/modprime
pytest utils
pytest mixnets/zeus_sk
pytest elections

exit 0
