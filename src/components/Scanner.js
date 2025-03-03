import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  Grid,
  Tabs,
  Tab,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SearchIcon from '@mui/icons-material/Search';

const Scanner = () => {
  const [domain, setDomain] = useState('');
  const [activeTab, setActiveTab] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState({
    subdomains: [],
    dns: {},
    urls: [],
    technologies: [],
    ports: [],
    sensitiveFiles: []
  });

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleScan = async () => {
    if (!domain) return;
    setScanning(true);

    try {
      const baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      
      // Fetch subdomains
      const subdomainsResponse = await fetch(`${baseUrl}/scan/subdomains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const subdomainsData = await subdomainsResponse.json();

      // Fetch DNS records
      const dnsResponse = await fetch(`${baseUrl}/scan/dns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const dnsData = await dnsResponse.json();

      // Fetch URLs
      const urlsResponse = await fetch(`${baseUrl}/scan/urls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const urlsData = await urlsResponse.json();

      // Fetch technologies
      const techResponse = await fetch(`${baseUrl}/scan/technologies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const techData = await techResponse.json();
      
      // Fetch ports
      const portsResponse = await fetch(`${baseUrl}/scan/ports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const portsData = await portsResponse.json();

      // Fetch sensitive files
      const sensitiveFilesResponse = await fetch(`${baseUrl}/scan/sensitive-files`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const sensitiveFilesData = await sensitiveFilesResponse.json();

      setResults({
        subdomains: subdomainsData.subdomains || [],
        dns: dnsData.dns_records || {},
        urls: urlsData.urls || [],
        technologies: techData.technologies || [],
        ports: portsData.ports || [],
        sensitiveFiles: sensitiveFilesData.sensitive_files || []
      });
    } catch (error) {
      console.error('Scanning error:', error);
    }

    setScanning(false);
  };

  const renderResults = () => {
    switch (activeTab) {
      case 0: // Subdomains
        return (
          <List>
            {results.subdomains.map((subdomain, index) => (
              <ListItem key={index}>
                <ListItemText primary={subdomain} />
              </ListItem>
            ))}
          </List>
        );

      case 1: // DNS Records
        return Object.entries(results.dns).map(([type, records]) => (
          <Accordion key={type}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography>{type.toUpperCase()} Records</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {records.map((record, index) => (
                  <ListItem key={index}>
                    <ListItemText primary={record} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        ));

      case 2: // URLs
        return (
          <Box>
            <Typography variant="h6" gutterBottom>Discovered URLs</Typography>
            <List>
              {results.urls.map((url, index) => (
                <ListItem key={index}>
                  <ListItemText primary={url} />
                </ListItem>
              ))}
            </List>

            <Typography variant="h6" sx={{ mt: 3 }} gutterBottom>Parameters & Form Fields</Typography>
            <List>
              {(results.parameters || []).map((param, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={`${param.parameter} (${param.type || 'query'})`}
                    secondary={
                      <>
                        URL: {param.url}
                        {param.method && <>
                          <br />
                          Method: {param.method}
                        </>}
                        {param.example_value && <>
                          <br />
                          Example Value: {param.example_value}
                        </>}
                      </>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        );

      case 3: // Technologies
        return (
          <List>
            {results.technologies.map((tech, index) => (
              <ListItem key={index}>
                <ListItemText primary={tech} />
              </ListItem>
            ))}
          </List>
        );

      case 4: // Ports
        return (
          <List>
            {results.ports.map((port, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={`Port ${port.port} (${port.service})`}
                  secondary={`Status: ${port.state}`}
                />
              </ListItem>
            ))}
          </List>
        );

      case 5: // Sensitive Files
        return (
          <List>
            {results.sensitiveFiles.map((file, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={file.path}
                  secondary={`Status: ${file.status} - ${file.url}`}
                />
              </ListItem>
            ))}
          </List>
        );

      default:
        return null;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Web Reconnaissance Tool
      </Typography>

      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={8}>
            <TextField
              fullWidth
              label="Enter Domain"
              variant="outlined"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <Button
              fullWidth
              variant="contained"
              color="primary"
              onClick={handleScan}
              disabled={scanning || !domain}
              startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <SearchIcon />}
            >
              {scanning ? 'Scanning...' : 'Start Scan'}
            </Button>
          </Grid>
        </Grid>
      </Paper>

      <Paper sx={{ width: '100%', bgcolor: 'background.paper' }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          indicatorColor="primary"
          textColor="primary"
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Subdomains" />
          <Tab label="DNS Records" />
          <Tab label="URLs" />
          <Tab label="Technologies" />
          <Tab label="Ports" />
          <Tab label="Sensitive Files" />
        </Tabs>

        <Box sx={{ p: 2 }}>
          {renderResults()}
        </Box>
      </Paper>
    </Box>
  );
};

export default Scanner;