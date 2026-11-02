# Installation
Clone or download this repository and open a terminal in its top directory. Install Python 3.10 or newer. The deterministic path uses only the standard library.

For live assessment install Ollama, start the local Ollama service, and run these commands before the demo:

    ollama pull llama3.2
    ollama list
    python triage.py --report example.txt --model llama3.2

Downloading a model needs network access and disk space. The adapter calls localhost port 11434. If it cannot connect, check the service and model name. For a repeatable offline scoring demonstration use the first command in the demo guide.
