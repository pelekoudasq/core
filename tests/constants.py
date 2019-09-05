"""
Contains constants for testing
"""

from crypto.modprime import ModPrimeSubgroup, ModPrimeElement, ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE
from mixnets import Zeus_sk


# -- Small algebraic objects --

RES11_GROUP = ModPrimeSubgroup(11, 2)             # quadratic residues mod 11

_00_ = ModPrimeElement(0, 11)
_01_ = ModPrimeElement(1, 11)
_02_ = ModPrimeElement(2, 11)
_03_ = ModPrimeElement(3, 11)
_04_ = ModPrimeElement(4, 11)
_05_ = ModPrimeElement(5, 11)
_06_ = ModPrimeElement(6, 11)
_07_ = ModPrimeElement(7, 11)
_08_ = ModPrimeElement(8, 11)
_09_ = ModPrimeElement(9, 11)
_10_ = ModPrimeElement(10, 11)


# -- Cryptosystems --

RES11_SYSTEM = ModPrimeCrypto(11, 2, allow_weakness=True)
RES11_SYSTEM = ModPrimeCrypto(11, 2, allow_weakness=True)
_2048_SYSTEM = ModPrimeCrypto(_2048_PRIME, _2048_PRIMITIVE)
_4096_SYSTEM = ModPrimeCrypto(_4096_PRIME, _4096_PRIMITIVE)


# -- Private/public keypairs (numerical constants) --

# Keypair in residues mod 11 cryptosystem

RES11_KEY = 4
RES11_PUBLIC = 3

# Keypair in _2048_PRIME cryptosystem

_2048_SECRET = 1469094658184849175779600697490107440856998313689389490776822841770551060089241836869172678278809937016665355003873748036083276189561224629758766413235740137792419398556764972234641620802215276336480535455350626659186073159498839187349683464453803368381196713476682865017622180273953889824537824501190403304240471132731832092945870620932265054884989114885295452717633367777747206369772317509159592997530169042333075097870804756411795033721522447406584029422454978336174636570508703615698164528722276189939139007204305798392366034278815933412668128491320768153146364358419045059174243838675639479996053159200364750820
_2048_PUBLIC = 5394597941056801896526782190476716288074277275570814559754703866276562647500523012388690063057160807778153187047259824591635207025668055120787003126814720675716390168377637021807819745434652332303397691222622910864476331548821005602850237180241000909653077436003921679484040512041420567544749245598200428971156726630493412314561553107131306400986632118245784330284667887403959705393503699955712251784418968134802522402637645636496700342801455227251279115845116050818605641774659455298584499558168602799711613987164546898545888686163402140639946396632584588779452784548267932902263570101883987959838617670179077049551

# Keypair in _2048_PRIME cryptosystem

_4096_SECRET =  347933544049795511827798129172072110981142881302659046504851880714758189954678388061140591638507897688860150172786162388977702691017897290499481587217235024527398988456841084908316048392761588172586494519258100136278585068551347732010458598151493508354286285844575102407190886593809138094472405420010538813082865337021620149988134381297015579494516853390895025461601426731339937104058096140467926750506030942064743367210283897615531268109510758446261715511997406060121720139820616153611665890031155426795567735688778815148659805920368916905139235816256626015209460683662523842754345740675086282580899535810538696220285715754930732549385883748798637705838427072703804103334932744710977146180956976178075890301249522417212403111332457542823335873806433530059450282385350277072533852089242268226463602337771206993440307129522655918026737300583697821541073342234103193338354556016483037272142964453985093357683693494958668743388232300130381063922852993385893280464288436851062428165061787405879100666008436508712657212533042512552400211216182296391299371649632892185300062585730422510058896752881990053421349276475246102235172848735409746894932366562445227945573810219957699804623611666670328066491935505098459909869015330820515152531557
_4096_PUBLIC = 858084424424515092806956255933743081397218780459040277756741074889205284107238004817504652755960390549419740916327557971825168776824077198417100178062729365652733237132918090421845209033402399808840940390093633470926938023465212129494765152077336871462928835926248034259455478021235358837748744927624906110051249348721519237166935952625467868218722512756670729029758122766572819722358817181558583993966745976073205682996697984046676362498806831488251571632117289086636124036603433016140525895627134631166439101900113041781599095336788340587924123366937353451758855766927913443830979017437000279920532739071248512760160194123590095598025062055662641766879957727433610284502158118145894214853792387228566183081048435904247648934921129688219514545923782625618541651885332356612681571170351061361868490689398595102030689143428212522244401030573647879079479955442765701875688817204984445881870609019695782626861323969833686480457903181978294338958209414959240971511162468465301112629397512099564473145206670607144824708280912660708683085884433654305161484326619471463124119553524026934388980996035408350278259183045185480110923465163301295217813006355879555341612889093867325073919963194164833775259901478498358682682252977005206637780887


# -- Election keys (ModPrimeElements) --

RES11_ELECTION_KEY = RES11_SYSTEM.group.random_element()
_2048_ELECTION_KEY = _2048_SYSTEM.group.random_element()
_4096_ELECTION_KEY = _4096_SYSTEM.group.random_element()


# -- Sako-Killian Mixnets --

RES11_ZEUS_SK = Zeus_sk({
    'cryptosystem': RES11_SYSTEM,
    'nr_rounds': 100,
    'nr_mixes': 24
}, election_key=RES11_ELECTION_KEY)

_2048_ZEUS_SK = Zeus_sk({
    'cryptosystem': _2048_SYSTEM,
    'nr_rounds': 20,
    'nr_mixes': 24
}, election_key=_2048_ELECTION_KEY)

_4096_ZEUS_SK = Zeus_sk({
    'cryptosystem': _4096_SYSTEM,
    'nr_rounds': 7,
    'nr_mixes': 24
}, election_key=_4096_ELECTION_KEY)


# -- Verificatum mixnets --


# -- Candidates --

choices = [
    'Party-A: 0-2, 0',
    'Party-A: Candidate-0000',
    'Party-B: generator0-2, 1',
    'Party-B:l Candidate-0001'
    'Party-C:l Candidate-0x00']

# -- Messages --

MESSAGE = 'l’esprit de sérieux est l’attitude de ceux qui pensent que \
les valeurs morales pré-existent à l’homme'

# -- DDH tuples --

# DDH in mod 11 residues cryptosystem --

RES11_DDH = {
    'ddh': (5, 3, 9),
    'log': 9                # the second member's logarithm
}

# DDH in mod _2048_PRIME cryptosystem --

_2048_DDH = {
    'ddh': (
        12829836400101040233808682829238881078046607563923619002314067184140219368126549947186480437194446863852009302221211930909191145585958148777387002230441921646343122190546684582104177781349128921987046095823539199276716911129690378267636653183350994992469170844721635657036392093449726260967592610336336096720234389903025720551373813518155484449800855319448985639601731716028740614585360620101917788577251282727248764432375940819729935573430928164106477238553097191048717532730209684408612724268495292999417506396758938294500246333396963291786874374365512003458761096801912715025235102161665677229662866852770766441363,
        1932191053538338121226626470638390939773333406748967376938718917542428076331630673256442238551035999060203017419041349980719150630316950417230516736012537493954402918671037864564662781481096905780859197584459261312841944128574548884087266461810287853309775705591409203741684161154031636232255299481515724678241225290507261902746183305536104141676564777730877076576647754003786023867335434862248034475312858997879944521529921403631820519231065930263902020890462276100610172700228882463512690227981421677233179334574165965515993946173736774432575220449144773574927629472270092526541755762130074828616300563416633726085,
        14819818551275329082686795199783720226940322561561588267682194494945852154219974458869750473254580707058264623523348497619740086543376561403818733632372610596082662465820380010474555988257637752759692599223468778327969403953441456336570604355323476360889200499713362117177178541389581489412975677589120797782691725558261635293349298013711878169620588128570646604378099323765456163391794712604098100479019054924229886703815513813851704421783347795696030676062435537410758711619339618944755050215920036668505903471029797410963088775276647260573126869465329997533199795988734390867259910544300994030815226562072521119966
    ),
    'log': 879871094019237  # the second member's logarithm
}


# DDH in mod _4096_PRIME cryptosystem

_4096_DDH = {
    'ddh': (
        23059460920629751948059473189880596577003665079498256233742623211817336628508902244710745024752194852914305767988511807556721466998848879800791653555807449940113295850490635920920157225364033216351308328083371744033259573974195290282828306849480324408220572623360165205795930387101406550356928981057336978989453053777373898027528853442261873140176031266365754210263351598190095175362611593079632775332126189982885269503270015888002793120172549821345885724923637849402338179216587451013794209991546884397368602044136249232354447266596593188922037128099875406101584068012424344177025229799459891535084192886903026597445564421676145137397241517342722421469577648631552019337805060253855382910772229266646037926453878989897251604267256343030549706237195559781988343441998259704646798598370872837210897920750725698122021432984331579330037392570047264341711487334371998228566453626298065771457180190664670361944003404602531168164823050312565079254758273988122351561064808404821204995719898302672313525428195656005126037061807191350414226673383276644295829920123684265174233889549629132519127704368026380851940992573124405659886736853146256027457919819948882759389079494895360128384678944350201368087087156714733843520068704146943656766106,
        289367120600850736888079060307268773979060245061805808262983255601714398080585759968684656474234197005267531246381301964417141541639880871555375653330094455934709617720179022125046092781988256462064297019231884783334145617628385608864397622399393565630409800946209657543864543595324583130284273449293353569497180781416679944830759725057876025754607647058786118626929431715210248671381681836862201266474555022226851655622485395064551758243682117323699884707416340766945907532536163059014213066652592887305987771411261154623097966666887108034015692221512423456408470889164038903667251864271982844596169216197422423667479528436532515866902121452385360085610964827238214005804653072782727098805078221621344208678606448540117586412798817870381844285690657078864159412073387714424756022620817627508828705674250160221697998570291537863345106294144576120879434227014767815882991250691069921920645109831925956043960609831234216019146748708672632041789466011478914847523528012538115869653707980238764704617942262324623570048359598667973209373216854741338494084251838164276737963486220913775138993733563400194331348299711294459202628790585831015279904317306578354538871576496416716005342495782911818280257963285378196749702337554841110374236462,
        781799878101393155240723295591140309971081943059629454293266354023487074478133496997847085516360483816630557851621966190461725819794435248462529468135380247472353431022241788623329708445387785200389506829118968879644756084137848287146906684213346551959709521378011299258808269260561206420082455995593580626842503353074842856722007758684034991760165694143601510570583035803335261205456256167047278762486476828698800379108012481742316204525235424165253365509744818183740097571654441488580316018936451432487195626407368095258131644297890789977947385828598316304104345714376266062528380411109498649370143603460064024050379193212915009408358900692866800847327938951413220066720024224919321730750387215406484115946840383704228232874255171794713939917352192287851924493497272812841679063733980549876943515723207340212947021045250325665392434840042028062218069264922280254523447725637626874994617546173554742734200780144036268103800583615777556869087307831577422790427353359285136296201216875580307965137650323599397925127443501898057217433720857193271888948105246036932568270211491965642600289013706072647573069828854424850377664401734158074916585836585077007636286597331038087480273297334966105667157325638467916037132237549208335420525883
    ),
    'log': 879871094019237  # the second member's logarithm
}
