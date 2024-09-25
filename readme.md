# Encrypted Endpoints

This project is designed to combat web bots by implementing encrypted endpoints, which are unique to each user account. Traditional obfuscation techniques and CAPTCHA mechanisms are becoming less effective due to advances in machine learning and bot automation. By using encrypted endpoints, this project aims to make it significantly more difficult for bots to scale across multiple accounts, as each bot instance would need to extract user-specific URLs. This approach helps mitigate common bot-related issues such as data scraping, spam, and fake interactions.

This project, part of a research paper to be published at the RAID 24 conference, demonstrates the implementation of encrypted endpoints to counter bot scalability. Development will continue following the official publication at the start of October, with further enhancements and features planned.


## Overview

A practical example is provided to show how encrypted communication between the client and server can be set up using FastAPI. This method ensures that data transmitted over the network remains secure and unreadable by third parties.

A demonstration video (`demo.mp4`) is included in the repository to showcase this approach in action.

## Project Structure

The project is structured as follows:

- `fastapi-example`: Contains all the test code.
- `fastapi-example/ee`: Houses the middleware implementing the encryption approach.

## Requirements

The example has been tested with **Python 3.12** please use this version.

### Installation

To install the necessary dependencies, run the following command:

```bash
pip install -r requirements.txt
```

### Running the Example

To start the example application, navigate to the project directory and run the FastAPI server using `uvicorn`:

```bash
cd fastapi-example
uvicorn main:app --reload
```