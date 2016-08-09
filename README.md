# Overview

WordPress is web software you can use to create a beautiful website, blog, or app. We like to say that WordPress is both free and priceless at the same time.
The core software is built by hundreds of community volunteers, and when you’re ready for more there are thousands of plugins and themes available to transform your site into almost anything you can imagine. Over 60 million people have chosen WordPress to power the place on the web they call “home” — we’d love you to join the family.

# Usage

## General Usage

To deploy a WordPress service on IIS:

    juju deploy --repository=/path/to/this/charm local:win2012r2/wordpress-iis

As a database backend, WordPress currently uses [MySQL](https://www.mysql.com) with which it comes preinstalled but can also connect to another MySQL machine with a Juju relation

To add a relation with the MySQL database charm:

    juju deploy mysql
    juju add-relation wordpress-iis mysql

# Configuration

* `site-name` - WordPress title
*
* `site-path` - The web server's path where to install WordPress. Leave empty to deploy in the root path or fill in a custom path where you want to deploy it. Example: if you set this field to 'blog' then you can visit the installation at http://wordpress-iis-hostname-or-ip/blog .

* `admin-password` - Password to set/update for the admin account. The admin user is preconfigured and hardcoded to 'Administrator'.

* `admin-mail` - The e-mail of the admin account 'Administrator'.

* `database-name` - The database name to be used by WordPress.

* `database-user-name` - The database username to be used by WordPress.

NOTE: Both the database-name and database-user-name can be changed at any time. The charm is configured to migrate the database from the previously set database to the new database.

To dynamically change a config option:

    juju set wordpress-iis <config_option>=<config_value>
