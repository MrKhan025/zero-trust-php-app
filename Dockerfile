FROM php:8.4-fpm-alpine

# Install system dependencies and libsodium
RUN apk add --no-cache \
    libsodium-dev \
    sqlite-dev \
    && docker-php-ext-install pdo pdo_sqlite sodium opcache

# Harden PHP production configuration
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
    && echo "expose_php = Off" >> "$PHP_INI_DIR/conf.d/zerotrust.ini" \
    && echo "display_errors = Off" >> "$PHP_INI_DIR/conf.d/zerotrust.ini" \
    && echo "session.use_strict_mode = 1" >> "$PHP_INI_DIR/conf.d/zerotrust.ini" \
    && echo "session.cookie_httponly = 1" >> "$PHP_INI_DIR/conf.d/zerotrust.ini" \
    && echo "session.cookie_samesite = Strict" >> "$PHP_INI_DIR/conf.d/zerotrust.ini" \
    && echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source" >> "$PHP_INI_DIR/conf.d/zerotrust.ini"

WORKDIR /var/www/zerotrust
COPY . /var/www/zerotrust

RUN mkdir -p storage/database storage/logs storage/cache \
    && chown -R www-data:www-data /var/www/zerotrust/storage \
    && chmod -R 750 /var/www/zerotrust/storage

USER www-data
EXPOSE 9000
CMD ["php-fpm"]
