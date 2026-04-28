#!/bin/bash

echo 'ACTION=="remove", SUBSYSTEM=="input", ENV{ID_INPUT_MOUSE}=="1", ENV{ID_VENDOR_ID}=="25a7", ENV{ID_MODEL_ID}=="fa67", RUN+="/usr/bin/loginctl lock-sessions"' | sudo tee /etc/udev/rules.d/99-lock-on-mouse-remove.rules
