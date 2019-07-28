import pytest
from math import floor

from crypto.algebra import (_mul, _divmod, _mod, _pow, _inv, isresidue,
                            make_cryptosys, make_schnorr_proof, make_schnorr_verify)
from crypto.constants import (_2048_PRIME, _2048_ELEMENT, _2048_KEY,
                              _4096_PRIME, _4096_ELEMENT, _4096_KEY)
from crypto.exceptions import (UnknownCryptoError, WrongConfigKeysError,
                               WrongCryptoError)


# Elementary integer operations

_2_ples_with_zeros = [(m, n) for m in range(0, 5) for n in range(0, 5)]

@pytest.mark.parametrize('m, n', _2_ples_with_zeros)
def test__mul(m, n):
    assert _mul(m, n) == m * n

_2_ples_without_zeroes = [(m, n) for m in range(0, 5) for n in range(1, 5)]

@pytest.mark.parametrize('m, n', _2_ples_without_zeroes)
def test__divmod(m, n):
    assert _divmod(m, n) == (floor(m / n), m % n)

@pytest.mark.parametrize('m, n', _2_ples_without_zeroes)
def test__mod(m, n):
    assert _mod(m, n) == m % n

_3_ples = [(m, n, r) for m in range(0, 5) for n in range(0, 5) for r in range(1, m ** n)]

@pytest.mark.parametrize('m, n, r', _3_ples)
def test__pow(m, n, r):
    assert _pow(m, n, r) == m ** n % r

modular_inverses = [
    (1, 1, 2),
    (1, 1, 3), (2, 2, 3),
    (1, 1, 4), (3, 3, 4),
    (1, 1, 5), (2, 3, 5), (3, 2, 5), (4, 4, 5),
    (1, 1, 6), (5, 5, 6),
    (1, 1, 7), (2, 4, 7), (3, 5, 7), (4, 2, 7), (5, 3, 7), (6, 6, 7)
]

@pytest.mark.parametrize('x, y, r', modular_inverses)
def test__inv(x, y, r):
    assert _inv(x, r) == y


# Tests powering inside Z^*_p for large p's

prime_and_element = [(_2048_PRIME, _2048_ELEMENT), (_4096_PRIME, _4096_ELEMENT)]

@pytest.mark.parametrize('p, a', prime_and_element)
def test_multiplicative_group_order(p, a):
    assert _pow(a, p - 1, p) == 1

@pytest.mark.parametrize('p, a', prime_and_element)
def test_multiplicative_subgroup_order(p, a):
    assert _pow(_pow(a, 2, p) , _divmod(p - 1, 2)[0], p) == 1


# Test modular residues

_modular_residues = [

    # (x, q, p), q = (p - 1)/r when checking for r-residues with p > 2

    # quadratic

    (1, 1, 3, True),

    (1, 2, 5, True), (2, 2, 5, False), (3, 2, 5, False), (4, 2, 5, True),

    (1, 3, 7, True), (2, 3, 7, True), (3, 3, 7, False), (4, 3, 7, True),
    (5, 3, 7, False), (6, 3, 7, False),

    (1, 5, 11, True), (2, 5, 11, False), (3, 5, 11, True),  (4, 5, 11, True),
    (5, 5, 11, True), (6, 5, 11, False), (7, 5, 11, False), (8, 5, 11, False),
    (9, 5, 11, True), (10, 5, 11, False),

    (
        19167066187022047436478413372880824313438678797887170030948364708695623454002582820938932961803261022277829853214287063757589819807116677650566996585535208649540448432196806454948132946013329765141883558367653598679571199251774119976449205171262636938096065535299103638890429717713646407483320109071252653916730386204380996827449178389044942428078669947938163252615751345293014449317883432900504074626873215717661648356281447274508124643639202368368971023489627632546277201661921395442643626191532112873763159722062406562807440086883536046720111922074921528340803081581395273135050422967787911879683841394288935013751,
        9968108389283139384500126851590910765388862256943492148736139047638818228043845477934450154869436209608798158762945749064212036697920030256947481168799132161279027615283393134357251369006458334758956359930154909543130908546999523713052822914048781317956011883544205342076807844957026467849313731346886391754340903453226366576558059611090955640495198876364264568947354655829865223811545250229670077826984304447786213073394010704828751390199575312681385536506430568502567177652698918604152960901576654034795592432088438139775481415636626281932952252619581888967324362795163037790197356322486462953657408538495400234553,
        _2048_PRIME,
        True
    ),

    (
        271256520111277162111866507456396787999066117314783852102358902860554406858891615654783091261011131734154325519369024575716788833974925157442688609510094398991071375577413080205880228758010295597422596208120927900699605926056305366960668066464675340446075592190056098633729435346563200103128120086809253191377871326822119728955765717889480811120628738217909169208846958663135883441971202453825924396201284622336839937882854937817971633602432210778852792846834593437807854067386641186384706851018066599035471037788937545395975326020513660568626421556254387449955797459312229291468367242162183429915786660778644798999521002686268164463982073381909715897951643617328051298667396838801568556769302010485977783519459605855422960136764823276134997191782701424539506101580212302163568509508810336551293231948445784991049069192201490861730248969439549754069137738144107129662904679359022720400914692433355869061220643051814537052935518433332484931286706438988547919314749839057335085249757258573425972316454301858532326474579951253417980692316533386101269271486520538034332872627950331279425930254910487890282299076907864170434718643270183153053314132500199249462129033190530209320765612167308293333094507518793534685148900454459151709082887,
        494869543292449603131435470747637580412214527780428843266913665088133047379269902947026232712771871379189028449458487844415021448732331829658282829340727668815963584858297194113943420910819674046815779432641218441351323689778440255331524448084594856447222707312886362866490182816679744962827576127598903938707782772724622667509074958672122195823355449395186907046354074174144904748074063633064416855356816906158372865395333247134567642709564869597101895474201474595128812657423184409701426319538373629402109084985740674072659431751071632117930274476476314680097902240477137975121105069151919761135711606830749552915095432249877819866449430874862131020031992644267523440468317192893495880208418029693746239146196148346561574003002252453628465863837174570302207717740783308300617181180581806359985996960637549763908297976054846951825589617769755104031537372533739221930709534816296235384400155514630495726739055095928424469281292171528505785425334334937101720628956829253752907865895732821306691868774442136891823760558098612255340770204028636716311831257732223955617243879278621246816838233704059919327573801926169957612761659746207347440598444410382412630808549409083709967678974577163957470985194734473060866913498549434519110408933,
        _4096_PRIME,
        True
    )

    # qubic
    # quadric
]

@pytest.mark.parametrize('x, q, p, _bool', _modular_residues)
def test_isresidue(x, q, p, _bool):
    assert isresidue(x, q, p) is _bool


# Cryptosystem construction

def test_UnknownCryptoError():
    with pytest.raises(UnknownCryptoError):
        make_cryptosys({'anything...'}, 'anything unsupported...')

_wrong_config__type = [
    (
        {'modulus': 5, 'root_order': 2, 'element':3, 'extra':0}, # extra field
        'integer'
    ),
    (
        {'modulus': 5, 'root_order': 2},                         # missing field
        'integer'
    ),
    (
        {'modulus': 5, 'wrong_field': 2, 'element':3},           # wrong field
        'integer'
    ),
]

@pytest.mark.parametrize('config, _type', _wrong_config__type)
def test_WrongConfigKeysError(config, _type):
    with pytest.raises(WrongConfigKeysError):
        make_cryptosys(config, _type)

_configs_and_parameters = [
    (
        _2048_PRIME,
        2,
        _2048_ELEMENT,
        9968108389283139384500126851590910765388862256943492148736139047638818228043845477934450154869436209608798158762945749064212036697920030256947481168799132161279027615283393134357251369006458334758956359930154909543130908546999523713052822914048781317956011883544205342076807844957026467849313731346886391754340903453226366576558059611090955640495198876364264568947354655829865223811545250229670077826984304447786213073394010704828751390199575312681385536506430568502567177652698918604152960901576654034795592432088438139775481415636626281932952252619581888967324362795163037790197356322486462953657408538495400234553,
        19167066187022047436478413372880824313438678797887170030948364708695623454002582820938932961803261022277829853214287063757589819807116677650566996585535208649540448432196806454948132946013329765141883558367653598679571199251774119976449205171262636938096065535299103638890429717713646407483320109071252653916730386204380996827449178389044942428078669947938163252615751345293014449317883432900504074626873215717661648356281447274508124643639202368368971023489627632546277201661921395442643626191532112873763159722062406562807440086883536046720111922074921528340803081581395273135050422967787911879683841394288935013751
    ),
    (
        _4096_PRIME,
        2,
        _4096_ELEMENT,
        494869543292449603131435470747637580412214527780428843266913665088133047379269902947026232712771871379189028449458487844415021448732331829658282829340727668815963584858297194113943420910819674046815779432641218441351323689778440255331524448084594856447222707312886362866490182816679744962827576127598903938707782772724622667509074958672122195823355449395186907046354074174144904748074063633064416855356816906158372865395333247134567642709564869597101895474201474595128812657423184409701426319538373629402109084985740674072659431751071632117930274476476314680097902240477137975121105069151919761135711606830749552915095432249877819866449430874862131020031992644267523440468317192893495880208418029693746239146196148346561574003002252453628465863837174570302207717740783308300617181180581806359985996960637549763908297976054846951825589617769755104031537372533739221930709534816296235384400155514630495726739055095928424469281292171528505785425334334937101720628956829253752907865895732821306691868774442136891823760558098612255340770204028636716311831257732223955617243879278621246816838233704059919327573801926169957612761659746207347440598444410382412630808549409083709967678974577163957470985194734473060866913498549434519110408933,
        271256520111277162111866507456396787999066117314783852102358902860554406858891615654783091261011131734154325519369024575716788833974925157442688609510094398991071375577413080205880228758010295597422596208120927900699605926056305366960668066464675340446075592190056098633729435346563200103128120086809253191377871326822119728955765717889480811120628738217909169208846958663135883441971202453825924396201284622336839937882854937817971633602432210778852792846834593437807854067386641186384706851018066599035471037788937545395975326020513660568626421556254387449955797459312229291468367242162183429915786660778644798999521002686268164463982073381909715897951643617328051298667396838801568556769302010485977783519459605855422960136764823276134997191782701424539506101580212302163568509508810336551293231948445784991049069192201490861730248969439549754069137738144107129662904679359022720400914692433355869061220643051814537052935518433332484931286706438988547919314749839057335085249757258573425972316454301858532326474579951253417980692316533386101269271486520538034332872627950331279425930254910487890282299076907864170434718643270183153053314132500199249462129033190530209320765612167308293333094507518793534685148900454459151709082887
    )
]

@pytest.mark.parametrize('p, r, g0, q, g', _configs_and_parameters)
def test_large(p, r, g0, q, g):

    cryptosys = make_cryptosys(config={
        'modulus': p,
        'root_order': r,
        'element': g0
    }, _type='integer')

    assert cryptosys == {
        'parameters': {
            'modulus': p,
            'order': q,
            'generator': g
        },
        'type': 'integer'
    }


_cryptosys_secret_public_extras__bool = [
    (
        {
            'parameters': {
                'modulus': _2048_PRIME,
                'order': 9968108389283139384500126851590910765388862256943492148736139047638818228043845477934450154869436209608798158762945749064212036697920030256947481168799132161279027615283393134357251369006458334758956359930154909543130908546999523713052822914048781317956011883544205342076807844957026467849313731346886391754340903453226366576558059611090955640495198876364264568947354655829865223811545250229670077826984304447786213073394010704828751390199575312681385536506430568502567177652698918604152960901576654034795592432088438139775481415636626281932952252619581888967324362795163037790197356322486462953657408538495400234553,
                'generator': 19167066187022047436478413372880824313438678797887170030948364708695623454002582820938932961803261022277829853214287063757589819807116677650566996585535208649540448432196806454948132946013329765141883558367653598679571199251774119976449205171262636938096065535299103638890429717713646407483320109071252653916730386204380996827449178389044942428078669947938163252615751345293014449317883432900504074626873215717661648356281447274508124643639202368368971023489627632546277201661921395442643626191532112873763159722062406562807440086883536046720111922074921528340803081581395273135050422967787911879683841394288935013751
            },
            'type': 'integer'
        },
        _2048_KEY,
        5394597941056801896526782190476716288074277275570814559754703866276562647500523012388690063057160807778153187047259824591635207025668055120787003126814720675716390168377637021807819745434652332303397691222622910864476331548821005602850237180241000909653077436003921679484040512041420567544749245598200428971156726630493412314561553107131306400986632118245784330284667887403959705393503699955712251784418968134802522402637645636496700342801455227251279115845116050818605641774659455298584499558168602799711613987164546898545888686163402140639946396632584588779452784548267932902263570101883987959838617670179077049551,
        [5, 7, 11, 666],
        True
    ),
    (
        {
            'parameters': {
                'modulus': _2048_PRIME,
                'order': 9968108389283139384500126851590910765388862256943492148736139047638818228043845477934450154869436209608798158762945749064212036697920030256947481168799132161279027615283393134357251369006458334758956359930154909543130908546999523713052822914048781317956011883544205342076807844957026467849313731346886391754340903453226366576558059611090955640495198876364264568947354655829865223811545250229670077826984304447786213073394010704828751390199575312681385536506430568502567177652698918604152960901576654034795592432088438139775481415636626281932952252619581888967324362795163037790197356322486462953657408538495400234553,
                'generator': 19167066187022047436478413372880824313438678797887170030948364708695623454002582820938932961803261022277829853214287063757589819807116677650566996585535208649540448432196806454948132946013329765141883558367653598679571199251774119976449205171262636938096065535299103638890429717713646407483320109071252653916730386204380996827449178389044942428078669947938163252615751345293014449317883432900504074626873215717661648356281447274508124643639202368368971023489627632546277201661921395442643626191532112873763159722062406562807440086883536046720111922074921528340803081581395273135050422967787911879683841394288935013751
            },
            'type': 'integer'
        },
        12345,
        5394597941056801896526782190476716288074277275570814559754703866276562647500523012388690063057160807778153187047259824591635207025668055120787003126814720675716390168377637021807819745434652332303397691222622910864476331548821005602850237180241000909653077436003921679484040512041420567544749245598200428971156726630493412314561553107131306400986632118245784330284667887403959705393503699955712251784418968134802522402637645636496700342801455227251279115845116050818605641774659455298584499558168602799711613987164546898545888686163402140639946396632584588779452784548267932902263570101883987959838617670179077049551,
        [5, 7, 11, 666],
        False
    ),
    (
        {
            'parameters': {
                'modulus': _4096_PRIME,
                'order': 494869543292449603131435470747637580412214527780428843266913665088133047379269902947026232712771871379189028449458487844415021448732331829658282829340727668815963584858297194113943420910819674046815779432641218441351323689778440255331524448084594856447222707312886362866490182816679744962827576127598903938707782772724622667509074958672122195823355449395186907046354074174144904748074063633064416855356816906158372865395333247134567642709564869597101895474201474595128812657423184409701426319538373629402109084985740674072659431751071632117930274476476314680097902240477137975121105069151919761135711606830749552915095432249877819866449430874862131020031992644267523440468317192893495880208418029693746239146196148346561574003002252453628465863837174570302207717740783308300617181180581806359985996960637549763908297976054846951825589617769755104031537372533739221930709534816296235384400155514630495726739055095928424469281292171528505785425334334937101720628956829253752907865895732821306691868774442136891823760558098612255340770204028636716311831257732223955617243879278621246816838233704059919327573801926169957612761659746207347440598444410382412630808549409083709967678974577163957470985194734473060866913498549434519110408933,
                'generator': 271256520111277162111866507456396787999066117314783852102358902860554406858891615654783091261011131734154325519369024575716788833974925157442688609510094398991071375577413080205880228758010295597422596208120927900699605926056305366960668066464675340446075592190056098633729435346563200103128120086809253191377871326822119728955765717889480811120628738217909169208846958663135883441971202453825924396201284622336839937882854937817971633602432210778852792846834593437807854067386641186384706851018066599035471037788937545395975326020513660568626421556254387449955797459312229291468367242162183429915786660778644798999521002686268164463982073381909715897951643617328051298667396838801568556769302010485977783519459605855422960136764823276134997191782701424539506101580212302163568509508810336551293231948445784991049069192201490861730248969439549754069137738144107129662904679359022720400914692433355869061220643051814537052935518433332484931286706438988547919314749839057335085249757258573425972316454301858532326474579951253417980692316533386101269271486520538034332872627950331279425930254910487890282299076907864170434718643270183153053314132500199249462129033190530209320765612167308293333094507518793534685148900454459151709082887
            },
            'type': 'integer'
        },
        _4096_KEY,
        264408728256410958632609076946284943167025135441393576296736405243824205098924506832342143112805616924903458649683777832826158979492526742894807078318472317106121035321309802172157333847475221592627658451419211954406180201808163064436308436089970713944819055819161835617181792006754917182394620670579203477162790993931364468922694595480797728599690862339847614610604485959489014096188540098289725683544167567949562744986423799178827144285362947012785019113968995410854277219437389007953889476279230765351330385766227632348852208886665545169674752561192033409207051979760833259490719562755544090602424339604008284291686407693480733622039107432929066000219469428630062105244680875654795405790323998147522410352113717135310856494783450491144129258711187287713119378038626724513342524484795717987570864163869032207446013484397568976811024459124770962180104122024141347327800871623210025382617641713389381670637247414054704076317953510386726465054721818750192297465708607946976327604065808840625672671931639067184892103375760094551016545039848197364229412263055159543641524459667384320272144165108398676778626845042471792774926709961235737394613810021737779584094439899821590101836278487910340437619087916474853470295355939356900659675446,
        [5, 7, 11, 666],
        True
    ),
]

@pytest.mark.parametrize(
    'cryptosys, secret, public, extras, _bool',
    _cryptosys_secret_public_extras__bool
)
def test_schnorr_protocol(cryptosys, secret, public, extras, _bool):

    schnorr_proof = make_schnorr_proof(cryptosys)
    schnorr_verify = make_schnorr_verify(cryptosys)

    proof = schnorr_proof(secret, public, *extras)
    assert schnorr_verify(public, proof, *extras) is _bool
