# Encrypted Endpoints Example Project

This project demonstrates how to implement encrypted endpoints using FastAPI for the backend and HTML, JavaScript, CSS for the frontend (via Jinja2 Templates). It support encrypted endpoints on user basis, as well as link sharing.

## Overview

A practical example is provided to show how encrypted communication between the client and server can be set up using FastAPI. This method ensures that data transmitted over the network remains secure and unreadable by third parties.

A demonstration video (`demo.mp4`) is included in the repository to showcase this approach in action.

## Project Structure

The project is structured as follows:

- `/src/fastapi-example`: Contains all the test code.
- `/src/fastapi-example/ee`: Houses the middleware implementing the encryption approach.

## Requirements

The example has been tested with Python 3.12.

### Installation

To install the necessary dependencies, run the following command:

```bash
pip install -r requirements.txt
```

### Running the Example

To start the example application, navigate to the project directory and run the FastAPI server using `uvicorn`:

```bash
cd ./src/fastapi-example
uvicorn main:app --reload
```