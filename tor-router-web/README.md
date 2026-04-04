# Tor Router Web (Nginx + PHP)

This folder mirrors the production web dashboard files deployed at:

- `/var/www/tor-router/index.html`
- `/var/www/tor-router/assets/app.js`
- `/var/www/tor-router/assets/style.css`
- `/var/www/tor-router/api/status.php`
- `/var/www/tor-router/api/control.php`

## Notes

- This is the advanced dashboard used for service control, troubleshooting, Tor rotation controls, and GeoIP view.
- Language switch (EN-US / PT-BR) is available from the flag buttons in the header.
- Tor rotation presets are available as one-click actions (5m, 10m, 30m, 1h).

## Deploy (manual sync)

```bash
sudo mkdir -p /var/www/tor-router/api /var/www/tor-router/assets
sudo cp tor-router-web/index.html /var/www/tor-router/index.html
sudo cp tor-router-web/assets/app.js /var/www/tor-router/assets/app.js
sudo cp tor-router-web/assets/style.css /var/www/tor-router/assets/style.css
sudo cp tor-router-web/api/status.php /var/www/tor-router/api/status.php
sudo cp tor-router-web/api/control.php /var/www/tor-router/api/control.php
```
