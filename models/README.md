# Models Directory - HarvestGuard

This directory is reserved for compiled model binaries, specifically the local **Qwen3-1.7B** model compiled for Qualcomm Neural Network (QNN) execution via ONNX Runtime.

## Target Model Architecture
- **Model**: Qwen3-1.7B
- **Execution Provider**: Qualcomm Neural Network (QNN) Execution Provider (`QNNExecutionProvider`)
- **Backend Runtime**: ONNX Runtime with Qualcomm Snapdragon NPU support (Hexagon DSP / HTP)

## Expected Directory Layout
```
models/
├── README.md
├── qwen3_1.7b_qnn.onnx            # ONNX graph definition
├── qwen3_1.7b_qnn.bin             # Weight binary / QNN model context
└── tokenizer/                     # Tokenizer configuration & vocab
    ├── tokenizer.json
    └── tokenizer_config.json
```

## Compilation & Export Notes
To compile the Qwen model for QNN EP:
1. Export model weights using the Qualcomm Neural Processing SDK (`qnn-onnx-converter` / `snpe-onnx-to-dlc`) or Qualcomm AI Engine Direct SDK.
2. Generate context binary targeting HTP (`htp_arch`: v73 / v75 / v68).
3. Ensure runtime library dependencies (`QnnHtp.dll` / `libQnnHtp.so` and `libQnnSystem.so`) are in system path or ONNX provider configuration path.
