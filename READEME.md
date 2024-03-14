This Project is a Proof of Concept Application to demonstrate how Vulnerability Scanners like `Grype` can be used to continuosly scan and monitor the security of Docker Images using Software Bill of Material (SBOM)s.

## Setup

To get up and running using docker the only thing you will have to do is to create a `.env` file in the root of the project and add the following environment variables:

```
# App's running environment
NODE_ENV="development"

# App's running port
PORT="3001"

# Cors Origin URL
CORS_ORIGIN="http://localhost:3000"

# App's public path
PUBLIC_PATH="/"
```

## Start

To start the application, run `docker compose up -d`.

## Stop

To stop the application, run `docker compose down`.

## Development

This application is built from the [Express TypeScript Boilerplate 2024](https://github.com/edwinhern/express-typescript-2024). Jest was replaced by vitest and the `prisma` ORM was added to the project.

To get up and runnning with develpment you will have to add the following environment variables to the `.env` file:

```
# This was inserted by `prisma init`:
# Environment variables declared in this file are automatically made available to Prisma.
# See the documentation for more detail: https://pris.ly/d/prisma-schema#accessing-environment-variables-from-the-schema

# Prisma supports the native connection string format for PostgreSQL, MySQL, SQLite, SQL Server, MongoDB and CockroachDB.
# See the documentation for all the connection string options: https://pris.ly/d/connection-strings

DATABASE_URL="postgresql://root:root@localhost:5432/vulnScan"
```

Since there is only a docker-compose setup for the "production" environment, you will have to start the database by running

```bash
docker compose up -d db
```

After that you will have to run the following commands to start the application:

```bash
# Install the dependencies
npm install

# Initialize the database using the prisma.schema file
npx prisma migrate dev

# Start the application
npm run dev
```

Now you are ready to start making changes to the application.

## Test

To run the tests, run `npm run test`.

## The way it works

The application is a simple API that allows you to create and read SBOMs of Docker Images. The SBOMs are stored in a PostgreSQL database using the Prisma ORM. After that the application uses the `grype` vulnerability scanner to scan the Docker Images and store the results in the database.

A new result is reduced to the following fields:

-   vulnerability.id (CVE or GHSA Identifier)
-   vulnerability.severity
-   vulnerability.cvss[number].metrics.baseScore
-   vulnerability.cvss[number].metrics.exploitabilityScore
-   vulnerability.cvss[number].metrics.impactScore
-   vulnerability.fix.versions
-   vulnerability.fix.state
-   matchDetails[number].type
-   artifact.name
-   artifact.version

and a hash of the result is calculated. If the hash is identical to the last one stored in the database, the result is not stored again, but a database entry is created with null values for result and resultHash fields to show that the image was scanned and the result is the same as the previous one. This is done to avoid storing the same or very similar results multiple times. If other fields are required to be checked for your prupose you can add them to the `computeGrypeResultDiffHash` function in the `src/modules/scan/scanService.ts` file.
