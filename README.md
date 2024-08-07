# Honeypot Example

This is an example honeypot project designed to log connections and gather information about potential attackers. The honeypot captures detailed user information, including device type, device version, browser version, IP address, country, city, and geo-coordinates.

## Features

- Logs connection details for multiple protocols: HTTP, FTP, Telnet, VNC
- Captures detailed device information using user-agent strings
- Fetches geolocation data for connecting IP addresses
- Provides a web dashboard for viewing logs and connection statistics
- Gracefully shuts down upon receiving termination signals

## Requirements

- Python 3.x
- Required Python packages (install using `pip`):

  ```bash
  pip install twisted flask matplotlib requests httpagentparser
  ```

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Dyst0rti0n/honeypot.git
    cd honeypot
    ```

2. **Install the required Python packages:**

    ```bash
    pip install twisted flask matplotlib requests httpagentparser
    ```

3. **Initialize the database:**

    ```bash
    python -c "import database; database.init_db()"
    ```

## Usage

1. **Run the honeypot services:**

    ```bash
    python honeypot_services.py
    ```

2. **Run the Flask web dashboard:**

    ```bash
    python app.py
    ```

3. **Access the web dashboard:**

    Open your browser and navigate to `http://localhost:5000` to view the honeypot logs and connection statistics.

## Project Structure

- `honeypot_services.py`: Main honeypot service script.
- `database.py`: Database initialization and logging functions.
- `geolocation.py`: Geolocation functions to fetch country and city data.
- `app.py`: Flask web application for displaying logs and statistics.
- `templates/index.html`: HTML template for the Flask web dashboard.

## Logging

The honeypot logs detailed information about each connection, including:

- Timestamp
- Protocol
- IP address
- Port
- Connection details
- User-agent string
- Device details (type, version, browser)
- Country and city

The logs are stored in a SQLite database (`honeypot.db`) and are also written to a log file (`honeypot.log`).

## Graceful Shutdown

The Flask web application includes signal handling for graceful shutdown. It listens for `SIGINT` and `SIGTERM` signals and shuts down cleanly upon receiving these signals.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue to discuss improvements or new features.
