#!/bin/bash

# Install frontend dependencies and build React application
npm install
npm run build

# Install backend dependencies
cd backend
pip install -r requirements.txt

# Return to root directory
cd ..