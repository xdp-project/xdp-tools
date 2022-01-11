#!/bin/bash

make test V=1 >> TEST_OUTPUT 2>&1
echo $? > TEST_RESULT
