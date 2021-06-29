const ffjavascript = require('ffjavascript')
const { Scalar } = require('ffjavascript')
const {Sigma, D, R,T, Y, Yis, Zis, Domain, Commitments} = require('./test-proof.js')

let bls12381 = null

function testG1Gen(bls12381) {
        if (!bls12381.G1.eq(bls12381.G1.add(bls12381.G1.neg(bls12381.G1.g), bls12381.G1.g), bls12381.G1.zero)) {
            throw("G1 * -G1 != 0")
        }
}

function G1Deserialize(serialized_g1) {
        if (serialized_g1.length != "192") {
            console.log(serialized_g1.length)
            throw("invalid length for g1 point")
        }

        let g1 = bls12381.G1.fromObject([
            Scalar.e('0x' + serialized_g1.slice(0, 96)),
            Scalar.e('0x' + serialized_g1.slice(96, 192)),
            Scalar.e("1")])
        return g1
}

/*
G1 generator serialization from blst python:

(Pdb) binascii.hexlify(blst.G1().serialize())
b'17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
*/
function testG1GenDeserialize(bls12381) {
        // format is x|y where x/y are 48bytes, big-endian and in normal form
        const serialized_g1 = '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'

        let g1 = G1Deserialize(serialized_g1)
        // g1 contains them in montgomery form now

        if (!bls12381.G1.eq(g1, bls12381.G1.g)) {
            throw("g1 deserialized != expected")
        }
}

function G1Gen() {
        const serialized_g1 = '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
        return G1Deserialize(serialized_g1)
}

function testFrDiv(bls12381) {
    let numerator = bls12381.Fr.e("1")
    let denominator = bls12381.Fr.e("75938438467018613505185840030189280574570304335288797782286941539983385173022")
    let result = bls12381.Fr.div(numerator, denominator)

    if (bls12381.Fr.toString(result) != '6895111531152973771500592584011752520924525831071581118085026095310658613421') {
        throw("division failed")
    }
}

async function checkProofSingle(commitment /* G1 */, proof /* G1 */, x /* Fr */, y /* Fr */, secret /* G2 */, bls12381) {
    let g2 = bls12381.G2.g
    let g1 = bls12381.G1.g

    let x_g2 = bls12381.G2.timesFr(g2, x)

    let SminusX = bls12381.G2.sub(secret, x_g2)
    // TODO why does go-verkle (and py-ecc?) produce the following value for previous g2 sub.  field extensions defined differently?
    /*
    let SminusX = bls12381.G2.fromObject([
        [Scalar.e("1193557042592112721288173917138204359901134424643355585098025015679548083423715813958365754670471099682462091103208"), Scalar.e("778791567935863601924538640408302293921001519338459249044453261628148386878242876641222136734118711916514481027967")],
        [Scalar.e("3924951945555214645101060899470911165588380091127123185083563599268702238099847033474609269832181621319468405639673"),
        Scalar.e("1358176085074515544225842837330921477510323131483689969438883884045834609879271088354350669324384462533525172019489")],
        [Scalar.one, Scalar.zero]])
    */

    let y_g1 = bls12381.G1.timesFr(g1, y)
    let commitmentMinusY = bls12381.G1.sub(commitment, y_g1)

    // example of pairing without pairingEq
    let p1 = bls12381.pairing(bls12381.G1.g, bls12381.G2.g)
    let p2 = bls12381.pairing(bls12381.G1.neg(bls12381.G1.g), bls12381.G2.g)
    let result = bls12381.F12.mul(p1, p2)
    if (!bls12381.F12.eq(result, bls12381.F12.one)) {
        throw("basic pairing check should work...")
    }

    // pairing example using pairingEq
    let pOne = bls12381.F12.one
    let res2 = await bls12381.pairingEq(bls12381.G1.g, bls12381.G2.g, bls12381.G1.neg(bls12381.G1.g), bls12381.G2.g)

    // check e([commitment - y], [1]) = e([proof],  [s - x])
    let res3 = await bls12381.pairingEq(commitmentMinusY, bls12381.G2.g, proof, SminusX)
    return res3
}

// proof consists of
// D - commitment
// sigma - ?
// y - ?
async function checkKZGMultiProof(multiproof, bls12381) {
        let g2_of_t = bls12381.Fr.e("0")
        let power_of_r = bls12381.Fr.e("1")

        // TODO compute r
        let r = bls12381.Fr.e(R)

        // TODO compute t
        let t = bls12381.Fr.e(T)

        let y = bls12381.Fr.e(Y)

        let domain = []
        let commitments = []
        let yis = []

        domain[0] = bls12381.Fr.e(Domain[0])
        commitments[0] = G1Deserialize(Commitments[0])
        yis[0] = bls12381.Fr.e(Yis[0])


        let d = G1Deserialize(D)
        let sigma = G1Deserialize(Sigma)

        let E = G1Gen()
        let E_tmp = G1Gen()

        for (let i = 0; i < 1; i++) {
            // E_coeff = r**i / (t - D[i])
            // why is (t - D[i]) not a modular arithmetic operation in dankrad's code?
            
            // TODO: calculate E_coeffs, C_i separately and then use multiexponentiation to get E
            // or.. do slower go-verkle way

            let E_coeff = bls12381.Fr.div(power_of_r, bls12381.Fr.sub(t, domain[i]))
            E_tmp = bls12381.G1.timesFr(commitments[i], E_coeff)
            if (i == 0) {
                E = E_tmp
            } else {
                E = bls12381.G1.add(E, E_tmp)
            }

            g2_of_t_tmp = bls12381.Fr.mul(E_coeff, yis[i])

            if (i == 0) {
                g2_of_t = g2_of_t_tmp
            } else {
                g2_of_t = bls12381.Fr.add(g2_of_t, g2_of_t_tmp)
            }

            power_of_r = bls12381.Fr.mul(power_of_r, r)
        }

        if (bls12381.G1.toString(bls12381.G1.toAffine(E)) !== "[ 2863729541235428038074680902469919598444056243294016551412581524402775855825918870718540951817007740496673787809381, 3803429439816810476289449546202412786626742571107793957759644254259286631166231648675238954486338073074716301387589 ]") {
            throw("calculate E failed")
        }

        if (bls12381.Fr.toString(g2_of_t,16) !== '28e9336dd28856c9d12753f0b7fcc1762629b6475f49549a7dcbcd09968b4b91') {
            throw("bad g2(t)")
        }

        let w = bls12381.Fr.sub(y, g2_of_t)

        // TODO calc q
        // let q = ...

        let q = bls12381.Fr.e("0x00c05af75ff19dd796afdc7002121f4003e1f4ebdd19e9fd04e84a097485f310")

        let fin = bls12381.G1.timesFr(d, q)
        fin = bls12381.G1.add(fin, E)

        if (bls12381.G1.toString(bls12381.G1.toAffine(fin)) !== '[ 2485367357624841870184630880365423354054457870827342932630250224385421682956280445567412527105499779092976866423233, 2924182078288239842491532911116314396141039828861356997766464230897415335947125071237343152797629017188019551124016 ]') {
            throw("bad fin value")
        }

        let finAt = bls12381.Fr.mul(w, q)
        finAt = bls12381.Fr.add(finAt, y)

        if (bls12381.Fr.toString(finAt, 16) !== '52c88c2276e617a3dbe517afadb4884f101954c96cd5d7a6790fcbda611ba502') {
            throw("bad finAt value")
        }

        let secret = bls12381.G2.fromObject([
            [Scalar.e("2128729237199874250215129762343714920720279411489563687929418278583868633058394659232382887990088775320953140642463"), Scalar.e("400479420466020439964245709617721188021173325950213531745899746559510361002891496236076189665548211399452952511078")],
            [Scalar.e("51862454752399442665654315116469814937243911105276497796352599957005996288034152334571289934845024913207096849346"), Scalar.e("2744214796388045889889136369721601905102309417661895746148694321349808889807430448570396683944137547401246256236596")],
            [Scalar.one, Scalar.zero]])

        let valid = await checkProofSingle(fin, sigma, t, finAt, secret, bls12381)
        if (!valid) {
            throw("pairing check failed")
        }

        console.log("done")
}

async function main() {
    bls12381 = await ffjavascript.buildBls12381(false)
    testG1Gen(bls12381)
    testG1GenDeserialize(bls12381)
    testFrDiv(bls12381)
    checkKZGMultiProof(null, bls12381)
}

main()
