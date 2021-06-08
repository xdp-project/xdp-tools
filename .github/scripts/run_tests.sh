#!/bin/bash

make test >> TEST_OUTPUT 2>&1
echo $? > TEST_RESULT