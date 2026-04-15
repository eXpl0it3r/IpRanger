from ipranger.app import create_app
from ipranger.config import config

if __name__ == '__main__':
    app = create_app()
    app.run(
        host=config.get('server', 'host', default='0.0.0.0'),
        port=config.get('server', 'port', default=5000),
        debug=config.get('server', 'debug', default=False)
    )
