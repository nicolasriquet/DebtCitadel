# DebtDojo

**DebtDojo** is a socio-technical debt management platform.

## Quick Start

```sh
git clone https://github.com/nicolasriquet/DebtDojo.git
cd django-DebtDojo
# building
./dc-build.sh
# running (for other profiles besides postgres-redis look at https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md)
./dc-up.sh postgres-redis
# obtain admin credentials. the initializer can take up to 3 minutes to run
# use docker-compose logs -f initializer to track progress
docker-compose logs initializer | grep "Admin password:"
```

Navigate to <http://localhost:8080>.


## Documentation


## Supported Installation Options


## Community, Getting Involved, and Updates


## Contributing


## Commercial Support and Training

## About Us

## License

DebtDojo is licensed under the [BSD-3-Clause License](LICENSE.md)
