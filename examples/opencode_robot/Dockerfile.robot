FROM fasp-harness:local

USER root
RUN pip install --no-cache-dir 'mujoco==3.16.0'
COPY robot_adapter.py /app/robot_adapter.py
USER fasp
