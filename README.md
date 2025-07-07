RouteAssistant: A Personalized and Proactive Smart Transportation System
RouteAssistant is a web-based intelligent transportation assistant designed to make daily commutes more predictable and stress-free. Instead of reactively checking traffic conditions, users can pre-define their routine routes, and the system will proactively send them an email alert if significant traffic delays are detected before their departure time.

This project was developed as a graduation project for a Computer Engineering degree.

Features
#User Authentication: Secure user registration and login system with password hashing.

#Role-Based Access Control: Separate access levels for regular users (user) and administrators (admin).

#Interactive Map: Users can add, edit, and delete personal locations (e.g., Home, Work) using an interactive Leaflet.js map.

#Multi-Modal Route Management: Full CRUD (Create, Read, Update, Delete) functionality for routes, supporting different transport modes (Car, Bicycle, Pedestrian).

#Personalized Alerts: Users can set custom departure times and traffic delay thresholds (%) for each route.

#Smart Notification System:

###A background scheduler (APScheduler) runs every minute to check upcoming departures.

###It integrates with the HERE Routing API to fetch real-time travel duration and traffic data.

###For "Car" routes, it calculates the delay percentage and sends an email alert if the user's threshold is exceeded.

###For "Bicycle" and "Pedestrian" routes, it sends a simple departure reminder with the estimated travel time.

#Admin Panel: An administrative dashboard to view system statistics and manage all users.

#Modern UI: AJAX-powered features for a smoother user experience, such as deleting locations without a full page reload.

Technologies Used
#Backend: Python, Flask, Flask-SQLAlchemy, APScheduler

#Frontend: HTML, CSS, JavaScript, Bootstrap 5

#Database: SQLite

#Mapping: Leaflet.js

#APIs & Services: HERE Routing API, Gmail SMTP
