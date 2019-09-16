import dns.resolver

from flask import abort, make_response

# Data to serve with our API

#Estructura de datos que representa los dominios
#   Tiene la responsabilidad de
#       * Cachear las IPs correspondientes a un dominio que resolvio por DNS
#           * domain : string
#           * ip : [string]
#           * custom : boolean
#       * Almacenar los custom domains ceados
#           * domain : string
#           * ip : string
#           * custom : boolean
dominios = {
    'martin.domain': {
        'domain': 'martin.domain',
        'ip': '999.999.999.999',
        'custom': True
    }
}

def resolveRoundRobin(domainCached, newsIps):
    """
    Esta funcion resuelve por Round Robin las IPs obtenidas al resolver el DNS de un dominio.
    Actualiza las IPs del dominio con las nuevas IP obtenidas.
    Si alguna de las IP deja de ser validas, se remueven del dominio cacheado. Si hay una nueva se agrega en ultimo lugar.
    Regresa segun metodo Round Robin la IP correspondiente.
    PRE: Recibe un dominio resuelto por DNS cacheado en sistema y un listado no vacio de las nuevas IPs resueltas por DNS
    POST: Modifica el dominio cacheado y devuelve la IP correspondiente por Round Robin. 
    """

    ipsCacheadas = domainCached.get('ip')
    ipsActualizadas = []

    #Limpiamos las IPs que ya no son validas
    for ipCacheada in ipsCacheadas:
        print("IP cacheada " + ipCacheada)
        if ipCacheada in newsIps:
            ipsActualizadas.append(ipCacheada)

    #Por Round Robin se devuelve la primera IP de las actualizadas
    returnIp = ipsActualizadas[0]

    #Agregamos las nuevas Ips validas
    for newIp in newsIps:
        print("IP nueva " + newIp)
        if newIp not in ipsActualizadas:
            ipsActualizadas.append(newIp)

    #Apllicamos Round Robin sobre los elementos
    ipsActualizadas.pop(0)
    ipsActualizadas.append(returnIp)

    #Actualizamos el cache
    domainCached['ip'] = ipsActualizadas

    return returnIp

def resolveDns(domain):
    """
    Esta funcion resuelve por DNS las IPs del dominio

    :return:        lista de las IPs asociadas al dominio
    """

    ips = []
    try:
        # Obtiene las resoluciones dns para este dominio
        result = dns.resolver.query(domain)
        ips = [ip.address for ip in result]
    except dns.resolver.NXDOMAIN as e:
        # El dominio no existe, por lo que las resoluciones dns permanecen vacias
        pass
    except dns.resolver.NoAnswer as e:
        # El resolver no responde, por lo que las resoluciones dns permanecen vacias
        pass
    return ips

def createDomain(domain,ip,custom):
    """
    Esta funcion crea la estructura de datos Dominio
    """

    domain = {
        'domain' : domain,
        'ip' : ip,
        'custom' : custom
    }
    return domain

def getDomain(domain):
    """
    Esta funcion maneja el request GET /api/domains/{domain}

     :domain body:  nombre del dominio el cual se resuelve el DNS para obtener su(s) IP(s) o bien se selecciona del sistema
    :return:        200 Dominio, 404 Dominio no encontrado en sistema o no se encontro IP por DNS
    """
    ##PREGUNTA: ¿Que se debe hacer primero, resolver dns o encontrar los customs?
    ##PREGUNTA: ¿Cacheamos los dominios del DNS y actualizamos el orden que regrese?
    ##PREGUNTA: ¿Que pasa si agregamos un custom domain que coincida con uno de dns? -> Creo que esto no deberia permitirse en el POST

    ips = resolveDns(domain)
    if not ips:
        if domain not in dominios:
            return abort(404, 'El Dominio solicitado no se encuentra en sistema o bien no se encontro IP por DNS')
        else:
            return dominios.get(domain)
    else:
        if domain not in dominios:
            cacheDnsDomain = createDomain(domain,ips,False)
            dominios[domain] = cacheDnsDomain
            return createDomain(cacheDnsDomain.get('domain'), resolveRoundRobin(cacheDnsDomain, ips), cacheDnsDomain.get('custom'))
        else:
            cacheDnsDomain = dominios[domain]
            return createDomain(cacheDnsDomain.get('domain'), resolveRoundRobin(cacheDnsDomain, ips), cacheDnsDomain.get('custom'))

def addDomain(**kwargs):
    """
    Esta funcion maneja el request POST /api/custom-domains

     :param body:  Dominio a crear en sistema
    :return:        201 Dominio creado, 400 Dominio existente en sistema o request mal formada
    """

    dominio = kwargs.get('body')
    domain = dominio.get('domain')
    ip = dominio.get('ip')
    custom = True

    if not domain:
        return abort(400, 'Parametro domain requerido no esta presente')
    if not ip:
        return abort(400, 'Parametro ip requerido no esta presente')

    dup = False
    for dominio_existente in dominios.values():
        dup = domain == dominio_existente.get('domain')
        if dup: break

    if dup:
        return abort(400, 'Dominio ya existente')

    dominioCreado = createDomain(domain,ip,custom)
    dominios[domain] = dominioCreado

    return make_response(dominioCreado, 201)

def modificar(**kwargs):
    """
    Esta funcion maneja el request PUT /api/custom-domains

     :param body:  Dominio a modificar en sistema
    :return:        200 Dominio modificado, 404 Dominio no encontrado en sistema, 400 Request mal formada
    """

    dominio = kwargs.get('body')
    domain = dominio.get('domain')
    ip = dominio.get('ip')

    if not domain:
        return abort(400, 'Parametro domain requerido no esta presente')
    if not ip:
        return abort(400, 'Parametro ip requerido no esta presente')

    if domain not in dominios:
        return abort(404, 'El Dominio solicitado no se encuentra en sistema')

    dominioAModificar = dominios.get(domain)
    dominioAModificar['ip'] = ip

    # Se retorna una copia del diminio modificado
    returnDomain = createDomain(dominioAModificar.get('domain'), dominioAModificar.get('ip'), dominioAModificar.get('custom'))

    return make_response(returnDomain,200)

def borrar(id_alumno):
    """
    Esta funcion maneja el request DELETE /api/alumnos/{id_alumno}

    :id_alumno body:  id del alumno que se quiere borrar
    :return:        200 alumno, 404 alumno no encontrado
    """
    if id_alumno not in alumnos:
        return abort(404, 'El alumno no fue encontrado')

    del alumnos[id_alumno]

    return make_response('', 204)