# eapi: An AST-Based Tool for Generating Swagger Documentation 🌐

![GitHub Release](https://img.shields.io/github/release/ChotThanachot/eapi.svg) ![GitHub All Releases](https://img.shields.io/github/downloads/ChotThanachot/eapi/total.svg)

Welcome to the **eapi** repository! This tool analyzes Abstract Syntax Trees (AST) to generate Swagger documentation. It is designed to work seamlessly with frameworks like **docs**, **gin**, **openapi**, and **swagger**. This README provides all the necessary information to help you get started and utilize the tool effectively.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Examples](#examples)
5. [Contributing](#contributing)
6. [License](#license)
7. [Links](#links)

## Features

- **AST Analysis**: Efficiently analyzes the structure of your code to create accurate Swagger documentation.
- **Framework Support**: Compatible with popular frameworks like docs, gin, openapi, and swagger.
- **Easy Integration**: Simple to integrate into your existing projects.
- **Customization**: Allows customization of the generated documentation to fit your needs.

## Installation

To install **eapi**, you can download the latest release from our [Releases page](https://github.com/ChotThanachot/eapi/releases). Please download the appropriate file for your operating system, and follow the instructions to execute it.

### Example Installation Steps

1. Visit the [Releases page](https://github.com/ChotThanachot/eapi/releases).
2. Download the appropriate binary for your OS.
3. Execute the binary from your terminal or command prompt.

## Usage

Using **eapi** is straightforward. After installation, you can generate Swagger documentation by running a simple command. 

### Basic Command

```bash
eapi generate [options]
```

### Options

- `--input`: Specify the input file or directory.
- `--output`: Define the output directory for the generated documentation.
- `--format`: Choose the format of the generated documentation (e.g., JSON, YAML).

### Example Command

```bash
eapi generate --input ./src --output ./docs --format yaml
```

This command will analyze the source files in the `src` directory and generate Swagger documentation in YAML format in the `docs` directory.

## Examples

### Example 1: Generating Basic Documentation

To generate basic documentation, you can run:

```bash
eapi generate --input ./myapi --output ./swagger-docs --format json
```

This command processes the `myapi` directory and outputs the Swagger documentation in JSON format.

### Example 2: Customizing Output

You can customize the output by specifying additional options:

```bash
eapi generate --input ./myapi --output ./swagger-docs --format yaml --title "My API Documentation"
```

This command adds a title to the generated documentation.

## Contributing

We welcome contributions to **eapi**! If you want to help improve the tool, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and create a pull request.

Please ensure your code adheres to the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Links

For more information, check the [Releases section](https://github.com/ChotThanachot/eapi/releases) for the latest updates and downloads. 

Feel free to explore the repository and contribute to making **eapi** even better!