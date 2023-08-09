# JS Secret Scanner

The **JS Secret Scanner** is a Python script designed to search for sensitive data patterns within javascript code obtained from a list of links. The script uses regular expressions to identify various types of sensitive information present in JavaScript files, such as API keys, access tokens, and other confidential data.

## Table of Contents

- [Description](#description)
- [Key Features](#key-features)
- [Usage](#usage)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [License](#license)

## Description

The JS Secret Scanner script fetches JavaScript content from provided links and searches for matches using a set of embedded regular expressions. If matches are found, it reports the sources of the matches and the type of sensitive information detected.

## Key Features

- Efficiently searches for various types of sensitive information in JavaScript files using regular expressions.
- Provides descriptions for different types of sensitive data patterns.
- Supports parallel processing using threading to speed up scanning.
- Offers a verbose mode to display detailed progress and messages.

## Usage

1. Clone or download this repository to your local machine.
2. Install the required Python libraries by running:
pip install requests colorama tqdm argparse

3. run the command: python jssecretscanner.py -i jslinks.txt

5. The script will process the links, search for sensitive data patterns in JavaScript files, and display the results.

## Prerequisites

- Python 3.x installed on your system.
- Internet connectivity to fetch content from the provided links.
- Basic understanding of regular expressions and handling sensitive data.

## Installation

1. Clone this repository:
git clone https://github.com/abhi-recon/jssecretscanner.git

2. Change directory: cd jssecretscanner

3. install requirements: pip install -r requirements.txt


## Usage Example

Suppose you have a file named `jslinks.txt` containing the following links:

https://example.com/main1.js

https://example.com/main2.js

https://example.com/main3.js


To scan these links for sensitive data in JavaScript files, you can run the script with the following command:

python jssecretscanner.py -i jslinks.txt

The script will start processing the links, analyzing JavaScript content, and display any matches it finds.

## License

This project is licensed under the [MIT License](LICENSE).

## Created By
Abhishek Karle

## Follow Me here -> https://twitter.com/AbhishekKarle3
