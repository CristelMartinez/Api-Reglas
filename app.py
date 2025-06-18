from flask import Flask, request, jsonify
from flask_cors import CORS
from librouteros import connect
import logging

app = Flask(__name__)
CORS(app)

# Configuración MikroTik
MIKROTIK_API_HOST = '192.168.88.1'
USERNAME = 'admin'
PASSWORD = '1234567890'
API_PORT = 8728

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_api():
    try:
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT
        )
        logger.debug("Conexión exitosa a MikroTik")
        return connection
    except Exception as e:
        logger.error(f"Error al conectar: {str(e)}")
        raise

@app.route('/sitios', methods=['POST'])
def controlar_sitio_web():
    """
    Controlar acceso a sitios web
    {
        "sitio_web": "www.youtube.com",
        "accion": "bloquear"  # o "permitir"
    }
    """
    data = request.get_json()
    sitio = data.get('sitio_web')
    accion = data.get('accion')

    if not sitio or accion not in ['bloquear', 'permitir']:
        return jsonify({'error': 'Se requiere sitio_web y acción (bloquear o permitir)'}), 400

    try:
        api = get_api()

        # Accede a layer7 y firewall
        l7_path = api.path('ip', 'firewall', 'layer7-protocol')
        reglas = api.path('ip', 'firewall', 'filter')

        # Define el patrón
        pattern = f".*{sitio}.*"
        l7_id = None

        # Verifica si ya existe el patrón Layer7
        for item in l7_path:
            if item.get('name') == sitio:
                l7_id = item['.id']
                break

        if not l7_id and accion == 'bloquear':
            resp = l7_path.add(name=sitio, regexp=pattern)
            # Manejo del tipo de respuesta
            if isinstance(resp, str):
                l7_id = resp
            elif isinstance(resp, dict):
                l7_id = resp.get('ret')

        if accion == 'bloquear':
            # Verificar si ya hay una regla con ese layer7-protocol
            for regla in reglas:
                if regla.get('layer7-protocol') == sitio and regla.get('action') == 'drop':
                    return jsonify({'message': f'El sitio {sitio} ya está bloqueado'}), 200

            reglas.add(
                chain='forward',
                protocol='tcp',
                action='drop',
                **{'layer7-protocol': sitio},
                comment=f"Bloqueado por API (sitio: {sitio})"
            )
            return jsonify({'message': f'Sitio {sitio} bloqueado correctamente'}), 200

        elif accion == 'permitir':
            eliminadas = 0
            # Eliminar reglas que tengan ese layer7-protocol
            for regla in reglas:
                if regla.get('layer7-protocol') == sitio and regla.get('action') == 'drop':
                    reglas.remove(regla['.id'])
                    eliminadas += 1

            # También eliminar el patrón Layer7 si existe
            for item in l7_path:
                if item.get('name') == sitio:
                    l7_path.remove(item['.id'])
                    break

            if eliminadas:
                return jsonify({'message': f'Sitio {sitio} desbloqueado ({eliminadas} regla(s) eliminadas)'}), 200
            else:
                return jsonify({'message': f'No había reglas de bloqueo para {sitio}'}), 200

    except Exception as e:
        logger.error(f"Error en el procedimiento: {str(e)}")
        return jsonify({'error': 'Error interno: ' + str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
