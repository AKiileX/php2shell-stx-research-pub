ARG PHP_IMAGE=php@sha256:d7974f6c6963b0136096e682f8e6b437dc2a1a96956e7e69e602c4796b9ee9ed
FROM ${PHP_IMAGE}

RUN docker-php-ext-install -j1 mysqli

ARG WORDPRESS_URL=https://wordpress.org/wordpress-7.1.3.tar.gz
ARG WORDPRESS_SHA256=d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5
RUN set -eux; \
    curl -fL --retry 3 -o /tmp/wordpress.tar.gz "${WORDPRESS_URL}"; \
    echo "${WORDPRESS_SHA256}  /tmp/wordpress.tar.gz" | sha256sum -c -; \
    rm -rf /var/www/html/*; \
    tar -xzf /tmp/wordpress.tar.gz --strip-components=1 -C /var/www/html; \
    rm /tmp/wordpress.tar.gz

COPY php.ini /usr/local/etc/php/conf.d/zz-production.ini
COPY apache.conf /etc/apache2/conf-available/zz-production-security.conf
COPY mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY wp-config.php /var/www/html/wp-config.php

RUN set -eux; \
    a2enmod headers; \
    a2enconf zz-production-security; \
    chown -R root:root /var/www/html; \
    find /var/www/html -type d -exec chmod 0755 '{}' +; \
    find /var/www/html -type f -exec chmod 0644 '{}' +; \
    mkdir -p /var/www/html/wp-content/uploads; \
    chown www-data:www-data /var/www/html/wp-content/uploads; \
    chmod 0775 /var/www/html/wp-content/uploads; \
    chown root:www-data /var/www/html/wp-config.php; \
    chmod 0640 /var/www/html/wp-config.php
