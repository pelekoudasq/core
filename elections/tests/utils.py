from crypto import ModPrimeCrypto
from crypto.constants import _2048_PRIME, _2048_PRIMITIVE, _4096_PRIME, _4096_PRIMITIVE
from mixnets import Zeus_sk

from ..stages import Uninitialized, Creating, Voting, Mixing, Decrypting, Finalized
from ..elections import ZeusCoreElection

def mk_election(config={
    'crypto': {
        'cls': ModPrimeCrypto,
        'config': {
            'modulus': _2048_PRIME,
            'primitive': _2048_PRIMITIVE
        }
    },
    'mixnet': {
        'cls': Zeus_sk,
        'config': {
            'nr_rounds': 2,
            'nr_mixes': 2
        }
    },
    'nr_parallel': 0,
    'zeus_private_key': None,
    'trustees': [
        {
            'value':   16307864018956986443635246553011081404122673474704699004472291385883486229312566799155367163108516441262056912671426881965859640906256661925430390332646779297733670095194792000199471609596664796089627494588671554139787396200810928785462530945938741450096919379648650838685691314924588406609020834365363925111709708680321584106939337272628304485791837459492545303648826173423662124790894141624251232219758584959265665437586818968304115785003189929275818165176017059111908405831677833961598529019748443523220170173904970428517293830381708888425156692483045920931176984008490206886579745750468817008930596616396807089754,
            'proof': {
                'commitment': 4867599769393829483447351739562961995013537935756510249794346466914916468686400399160195050916486607489325624825711863184286992293435242912062222723118139252350700006091991362144886325915605236928695242445670451095378883094931410739234920845238431301976510968030386886991721801987484747184104509331360270606119229134246319746471429919142288014638504258926507834385934213782594295534870993434064247444583128721657059463025882293889069197633705030957100485652995037898277065952434102560198663934593968385195282010160883992384398561058710223883291982378372218793061921108936429951433592403589614939362376951036919877813,
                'challenge': 7842521295901068986087149027395789637262734390808262503287639119134714552642605257325458980390697222860094665423456981878881786183422220292724203344479329821193949378797046680554821701246626033188664542793748407563862470681857723550253709525971664882904805249111555953749650512687717788032431632136431736344922748174856557892471460122739250132154082357653662248768931596949544738384021720901832376437778853726402735916643667525167531411757691200250696469243690419019830142347178483939136816868071587928616830549476247974465895370683573608044974926362055914118625990228432075182147472425462330060211673676458228903555,
                'response': 3587136190710904885992350204315503279867521346194385339965919262096402115700230151554370168954648507930037676155048253336590319975940430644052334389856303006409496173713263864279583824585390497772047089886149791468119975196785810147858574972814565189909065715738921843183969536950585654599061970703611282308666840492208311057159522185603045673018603025320774797064285851795879407655177580397764104268708742027491909743948079587501959444149649285640789622924911978916285958339541857335576486257267641407812197475180726957461038167380927412732195031826203357673311055358045417858259762392675442918532150024813055639714
                }
        },
        {
            'value': 9258198041266701824174373723492550025271902310999202569492866451059210467380027737967928644904006039983041048274984025074597152249546286535914653168380279551242977245805975576680729059594794107526528783682695172716320239097209022932810763766773406012117463862539336615339346462230045439424656018370823934641500573050209488540609678780260249039550067443451942842826901066383460807578163290426608716246285655895300149993644167179091776996554867181110788092823721626886668155156433448120797470179242735168743393624427988684860770076670683314682884783731805466296894586925114119068438220390161730058815193679052853207612,
            'proof': {
                'commitment': 6999443600452544048086541856819962841158742087085556353207045996067419320289998641713505362565347560663688109138420927226754993964706085262400192187531023020904110550696714996422238644168226809045080733578218385555376593144016105319129681278476724322267409496121691180960185051976825284790556582021396562436767263647548042867013387686541642542332809585038139182939184041575755833838354223582990767324165047925820568403080801473374063654909305050285702372783830981260424909203719266530732222711725394012733058834459907738177365916682106106783562384668005742949951260331753237790121107808935545485074683235693432381129,
                'challenge': 3911361810569990198097719126844421635840003227556181320618316886586617208513030709702047088122706490362297967202926815983941696936278142061069636903373386877465194299506275392322772990584448566679122776058873199877723218418212357846490872049330548539594508363172364822662012508488973872976629682379625480558242710152322406186953000694152066384305311331886560630450765267374213526491081795930010861393602175857474909279386177891187546115185447345051439552514503116876330342777946038754644201369670763197131857381236859533206684171642729709739662131221891710499902267000733023258704188117804736676387001730135367454531,
                'response': 6863126671988874579771302605242669622960450327961881438357637514678940046476441832979033176150295167119700785140275156084141152510036310510957554019809573862789657183162016461371296219118157386110314496026179906599186896276959612785838737749422566003975105525967552283838653980701586512909245402425106984251534830728683573952763984242733913756952991717669449465868796585848010320780961332644515706338636779408429400967487262026497288882410996568078371171422314798679547451943498441860931886165035826818217749318640924528435702875583916662207736383220772466435916174685709975767222513487365016295026357005944788935761
            }
        },
        {
            'value': 12330764496293879322411543685393978409728874077789073494979657091291902426967333925423614355814619646493691692330782795854170437918535581944623113176807061453677108610819955955551144669419266746885106022050601359421574018482507386421342005980677185840894063279208917742206938604126655173421465187600427512192129731381295069810055179975156925864062802213195797361473679864616408317937630001532273205455742527889687339179908285936455995306082305953258636624351994062001477986421656508955524553452435502887668156223294751844903159670749230829823694645202092224353960553455439135138929398622476873824617263867874218119897,
            'proof': {
                'commitment': 13066276925737211163124661013170076615932002417011048964429961881480678613658371602443396391890264011970383279894129358844898960671745259063530133287615376702462172699891760730120610981932936596469544732207908773180566158510515481400581145821765589804195761267760740493492406541779117993201946261053201600580557346528264858622044914667052088610677839740351092383659386159571374835974522178131530719673260428701058435530764117033274721572279733172994800244866454197135536896091921490543226754401101651641276520654769655174610430161333663777324445777364724936455545229121729392378433195678561961397089986010086885409013,
                'challenge': 16568627859915831855231558097961195971115332701711099901834105272380536717237347895852956405434035016040613751352380325204006591205208812611164870793298410207604963207797576112213371913970550430782547387199305511863144610222292018417589956329739304528177777577348950578724581021899401370665831450131100081042457011005436020488965146276725189479736977386326692886934137177110633310615307378330769731881319418547827331211350565975365907156872273066851225053087007111445326534969417356358779317714382894082876439032943761015797462239254958613467703179402919028987396103399704470947035554789686474275687644825675474907109,
                'response': 6687401473462954741096396070405782126331859751152923083333622340683393152183223742568393152905606753724882519859915936954065841547539450962206678987461776582955468140411078940836505391397770199945193449151817542171869527940181670368526419717284368365528033006113778183469944143247404641356124529813236658659484057677700948265152213892900091692528611396571465548616255067089343384492283489330705231089813579886746909998066443703008051912549010374169478450509923399384266119589311701152769813773187709763197879924408587868535830646741816053996960541082147210048311175458355227934053941298745972504911385395743529513028
            }
        }
    ],
    'candidates': [
        'Party-A: 0-2, 0',
        'Party-A: Candidate-0000',
        'Party-A: Candidate-0001',
        'Party-A: Candidate-0002',
        'Party-A: Candidate-0003'
        'Party-B: 0-2, 1',
        'Party-B: Candidate-0000',
        'Party-B: Candidate-0001',
        'Party-B: Candidate-0002',
    ],
    'voters': [
        ('Voter-00000000', 1),
        ('Voter-00000001', 1),
        ('Voter-00000002', 1),
        ('Voter-00000003', 1),
        ('Voter-00000004', 1),
        ('Voter-00000005', 1),
        ('Voter-00000006', 1),
        ('Voter-00000007', 1),
        ('Voter-00000008', 1),
        ('Voter-00000009', 1),
        ('Voter-00000010', 1),
        ('Voter-00000011', 1)
    ]
}):
    return ZeusCoreElection(config=config)

def run_until_uninitialized_stage(election):
    uninitialized = Uninitialized(election)
    return uninitialized

def run_until_creating_stage(election):
    uninitialized = Uninitialized(election)
    uninitialized.run()
    creating = uninitialized.next()
    return creating
