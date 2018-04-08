#!/bin/bash

pushd ios
  gomobile bind -v -target=ios github.com/mandelmonkey/lndmobile/lightning
popd
