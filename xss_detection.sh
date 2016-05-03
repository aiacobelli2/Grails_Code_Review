## Esta tools detecta potenciales xss mirando configs por default. 
## Configs
RED='\033[0;31m'
NC='\033[0m'

## Me aseguro que haya un parametro <path del proyecto a escanear>
if [ $# == 1 ]; then
	path="$1"

## Busco en Config.groovy la config del codec por default ##
	configGroovy="$(find $path -type f -name 'Config.groovy')"
	defaultCodec="$(grep -E -o 'grails.views.default.codec=[a-zA-Z\"]+' $configGroovy | grep -Eo '=[A-Za-z\"]+' | grep -Eo '[A-Za-z]+')"

	if [ ${defaultCodec} != 'html' ];then
		echo "${RED}[!] ${NC}Se detecto que su proyecto no tiene seteado el default encoding en 'html'. Si este proyecto es un frontEnd o una Api publica es recomendado setear este parametro a 'html'.\n Pasos para resolverlo:\n 1) Ir al 'Config.groovy' de su proyecto.\n 2) Modificar la linea que contenga 'grails.views.default.codec' a 'grails.views.default.codec=\"html\"'.\n Para mas info comunicarse con websec@.\n\n\n";
	else
		echo "[OK] ..."
	fi
## Busco salidas no encodeadas en GSP ##
## 1) Salidas no estandar <%= VAR %>

	badOutputs="$(grep -E -n -o '<%=[ A-Za-z0-9]+%>' $path -R | grep 'packageName' -v)"

	if [ -z "$badOutputs" ];then
		echo "[OK] ..."
	else
		echo "${RED}[!] ${NC}Se detectaron que los siguientes gsp no utilizan nomeclaturas estandar dejando a la aplicacion vulnerable a posibles ataques de XSS. Utilizar la forma estandar \${var} para devolver datos encodeados por deafult y en el caso de necesitar enviar un output sin encoding, utilizar la siguiente nomeclatura: \${raw(var)}. Evitar utilizar <% var %> \n"
		echo "#################################START#################################"
		echo "$badOutputs" | sed -e 's/\.\//\--->.\//g'
		echo "#################################END#################################\n"
		echo "\n\n\n\n"
	fi

## 2) Salidas de traduccion

	badOutputs2="$(grep -r --include=*.groovy -n '<%=t9n' $path -R | grep -E '\{0\}.*f:' | grep -E "encoding:\"none\"|encoding:'none'")"
	if [ -z "$badOutputs2" ];then
    	    echo "[OK] ..."
	else
    	    echo "${RED}[!] ${NC}Se detecto que las siguientes lineas en las que se usa el plugin \"I18n-gettext\" no utilizan encoding para el output, dejando a la aplicacion vulnerable a posibles ataques de XSS. Utilizar la siguiente nomeclatura segura: <%=t9n [..], encoding:\"html\")%> en lugar de <%=t9n [..], encoding:\"none\")%> en las siguientes lineas:  \n"
			echo "##################################################################START##################################################################"
			echo $badOutputs2 | sed -e 's/\.\//\'$'\n\.\//g' | sed -e 's/\.\//\--->.\//g'
			echo "##################################################################END##################################################################\n"	
			echo "\n\n\n\n"
	fi
## 3) Salida desde los .groovy

badOutputs3="$(grep -r --include=*.groovy '\${' ./ -n | grep -v "println" | grep -v "log.debug"| grep -v "def "| grep -v -E "if |if\(" | grep -v "log.info" | grep -v "log.error" | grep -v "// "| sed -e 's/\.\//\./g')"


echo "${RED}[!] ${NC}Los .groovy no son alcanzados por por la config global que se encuentra en el Config.groovy. Es por esto que es recomendable utilizar el metodo encodeAsHTML() para evitar potenciales XSS.\n\n"
echo "##################################################################START##################################################################"
echo $badOutputs3 | sed -e 's/\.\//\'$'\n\.\//g' | sed -e 's/\.\//--->\.\//g'
echo "##################################################################END##################################################################"

fi
