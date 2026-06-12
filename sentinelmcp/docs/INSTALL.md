# SentinelMCP Installation Guide

## Requirements
- Python 3.10+
- fastmcp >= 2.0.0
- anthropic >= 0.30.0

## Installation

You can install SentinelMCP directly via pip:

```bash
pip install .
```

This will make the `sentinelmcp` CLI entry point available globally.

## Development Setup

If you are developing or testing SentinelMCP, install the development dependencies:

```bash
pip install .[dev]
```

## Running the Agent

To start a triage session, provide the necessary disk, memory, or network capture paths:

```bash
sentinelmcp --disk /path/to/disk.E01 --memory /path/to/mem.dmp --pcap /path/to/capture.pcap
```

See the Operations Guide for more deployment and usage information.
