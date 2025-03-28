# EchoDesk Agent

**EchoDesk Agent** is an AI agent-powered helpdesk automation tool that simplifies user management tasks in Azure Active Directory (Azure AD) and Freshdesk. By leveraging Agents SDK, it interprets user requests, automates actions, and delivers real-time feedback through an intuitive interface.

## Features

- **Natural Language Processing**: Processes user requests written in plain English.
- **Azure AD Integration**: Automates account creation, updates, and management in Azure AD.
- **Freshdesk Integration**: Generates and updates tickets in Freshdesk for seamless tracking.
- **Real-Time Process Tracking**: Offers live updates on the status of background processes.
- **Database Persistence**: Retains process states across server restarts for reliability.

## Architecture

EchoDesk Agent is built with three core components:

- **Backend**: A FastAPI application that manages API requests, database interactions, and background tasks.
- **Frontend**: A single-page HTML app with JavaScript for user interaction and live updates.
- **Database**: An MSSQL database storing process states, ticket numbers, and persistent data.

## Prerequisites

Before setting up EchoDesk Agent, ensure you have the following:

- **Python 3.8+**
- **MSSQL Server**
- **FastAPI**
- **SQLAlchemy**
- **Pydantic**
- **OpenAI API Key**
- **Azure AD Credentials** (Tenant ID, Client ID, Client Secret)
- **Freshdesk API Key**

## Installation

Follow these steps to get EchoDesk Agent up and running:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/aghimir3/EchoDesk.git
   cd echodesk
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Create a `.env` file in the root directory and add:
   ```plaintext
   OPENAI_API_KEY=your_openai_api_key
   FRESHDESK_DOMAIN=your_freshdesk_domain
   FRESHDESK_API_KEY=your_freshdesk_api_key
   AZURE_TENANT_ID=your_azure_tenant_id
   AZURE_CLIENT_ID=your_azure_client_id
   AZURE_CLIENT_SECRET=your_azure_client_secret
   DATABASE_URL=mssql+pyodbc://username:password@server:port/database?driver=ODBC+Driver+17+for+SQL+Server
   DEFAULT_PASSWORD=your_default_password
   ```

5. **Run the Application**:
   ```bash
   uvicorn main:app --reload
   ```

6. **Access the Interface**:
   Open your browser and navigate to `http://localhost:8000`.

## Utility Scripts

To streamline development and troubleshooting, the project includes two utility scripts:

- **`hard-reset.sh`** (macOS/Linux) / **`hard-reset.bat`** (Windows):  
  Fully resets the environment by stopping processes, clearing caches, recreating the virtual environment, reinstalling dependencies, and starting Uvicorn. Use this for a clean slate (e.g., after major changes).

- **`run.sh`** (macOS/Linux) / **`run.bat`** (Windows):  
  Starts the application by stopping processes, clearing caches, activating the virtual environment, installing dependencies, and running Uvicorn. Ideal for daily use.

### Usage

- **macOS/Linux**:
  ```bash
  ./hard-reset.sh
  ./run.sh
  ```

- **Windows**:
  ```cmd
  hard-reset.bat
  run.bat
  ```

**Note**: For macOS/Linux, ensure the scripts are executable:
```bash
chmod +x hard-reset.sh
chmod +x run.sh
```

## Usage

Here’s how to use EchoDesk Agent:

1. **Submit a Request**:
   - In the textarea, type a request (e.g., "Create an account for Jane Doe with a Standard license").
   - Click "Submit Request" to initiate the process.

2. **Check Process Status**:
   - Enter a process ID in the input field and click "Submit Request" to see updates.
   - If a Freshdesk ticket is generated, a direct link to it will be displayed.

## API Documentation

Key endpoints include:

- **`POST /api/agent`**: Submit a new request.
- **`GET /api/process-updates/{process_id}`**: Fetch updates for a specific process ID.
- **`GET /api/config`**: Retrieve configuration details, including the Freshdesk domain.

For full API details, visit `http://localhost:8000/docs` after starting the server.

## Contributing

We’d love your contributions! Here’s how to get started:

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add your feature'
   ```
4. Push to your branch:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
