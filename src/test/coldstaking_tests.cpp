
#include <boost/test/unit_test.hpp>

#include "net.h"
#include "keystore.h"
#include "script.h"
#include "kernel.h"
#include "extkey.h"
#include "wallet.h"

BOOST_AUTO_TEST_SUITE(coldstaking_tests)

BOOST_AUTO_TEST_CASE(opiscoinstake_test)
{
    CBasicKeyStore keystoreA;
    CBasicKeyStore keystoreB;

    CKey kA, kB;
    kA.MakeNewKey(true);
    keystoreA.AddKey(kA);

    CPubKey pkA = kA.GetPubKey();
    CKeyID idA = pkA.GetID();

    kB.MakeNewKey(true);
    keystoreB.AddKey(kB);

    CPubKey pkB = kB.GetPubKey();
    CKeyID256 idB = pkB.GetID256();

    CScript scriptSignA = CScript() << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript scriptSignB = CScript() << OP_DUP << OP_HASH160 << ToByteVector(idB) << OP_EQUALVERIFY << OP_CHECKSIG;

    CScript script = CScript()
    << OP_ISCOINSTAKE << OP_IF
    << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
    << OP_ELSE
    << OP_DUP << OP_HASH160 << ToByteVector(idB) << OP_EQUALVERIFY << OP_CHECKSIG
    << OP_ENDIF;


    BOOST_CHECK(HasIsCoinstakeOp(script));

    BOOST_CHECK(!IsSpendScriptP2PKH(script));


    CScript scriptFail1 = CScript()
    << OP_ISCOINSTAKE << OP_IF
    << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
    << OP_ELSE
    << OP_DUP << OP_HASH160 << ToByteVector(idA) << OP_EQUALVERIFY << OP_CHECKSIG
    << OP_ENDIF;
    BOOST_CHECK(IsSpendScriptP2PKH(scriptFail1));


    CScript scriptTest, scriptTestB;
    BOOST_CHECK(GetCoinstakeScriptPath(script, scriptTest));
    BOOST_CHECK(scriptTest == scriptSignA);


    BOOST_CHECK(GetNonCoinstakeScriptPath(script, scriptTest));
    BOOST_CHECK(scriptTest == scriptSignB);


    BOOST_CHECK(SplitConditionalCoinstakeScript(script, scriptTest, scriptTestB));
    BOOST_CHECK(scriptTest == scriptSignA);
    BOOST_CHECK(scriptTestB == scriptSignB);


    txnouttype whichType;

    BOOST_CHECK(IsStandard(script, whichType));



    BOOST_CHECK(IsMine(keystoreB, script) & ISMINE_ALL);
    BOOST_CHECK(IsMine(keystoreA, script) & ISMINE_ALL);


    CAmount nValue = 100000;

    CTransaction txn;
    txn.nLockTime = 0;

    int nBlockHeight = 1;
    CTxOut outData;
    outData->vData.resize(4);
    memcpy(&outData->vData[0], &nBlockHeight, 4);
    txn.vout.push_back(outData);


    CTxOut out0;
    out0->nValue = nValue;
    out0->scriptPubKey = script;
    txn.vout.push_back(out0);
    txn.vin.push_back(CTxIn(COutPoint(uint256S("d496208ea84193e0c5ed05ac708aec84dfd2474b529a7608b836e282958dc72b"), 0))); // Check this hash
    BOOST_CHECK(txn.IsCoinStake());

    std::vector<uint8_t> vchAmount(8);
    memcpy(&vchAmount[0], &nValue, 8);



    BOOST_CHECK(SignSignature(&keystoreA, script, txn, 1, SIGHASH_ALL));
    BOOST_CHECK(!SignSignature(&keystoreB, script, txn, 1, SIGHASH_ALL));

}


BOOST_AUTO_TEST_SUITE_END()