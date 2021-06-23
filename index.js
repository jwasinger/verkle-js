const ffjavascript = require('ffjavascript')
const { Scalar } = require('ffjavascript')

let bls12381 = null

function testG1Gen(bls12381) {
        if (!bls12381.G1.eq(bls12381.G1.add(bls12381.G1.neg(bls12381.G1.g), bls12381.G1.g), bls12381.G1.zero)) {
            throw("G1 * -G1 != 0")
        }
}

/*
G1 generator serialization from blst python:

(Pdb) binascii.hexlify(blst.G1().serialize())
b'17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
*/
function testG1GenDeserialize(bls12381) {
        // format is x|y where x/y are 48bytes, big-endian and in normal form
        const serialized_g1 = '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'

        let g1 = bls12381.G1.fromObject([
            Scalar.e('0x' + serialized_g1.slice(0, 96)),
            Scalar.e('0x' + serialized_g1.slice(96, 192)),
            Scalar.e("1")])
        // g1 contains them in montgomery form now

        if (!bls12381.G1.eq(g1, bls12381.G1.g)) {
            throw("g1 deserialized != expected")
        }
}

function testFrDiv(bls12381) {
    let numerator = bls12381.Fr.e("1")
    let denominator = bls12381.Fr.e("75938438467018613505185840030189280574570304335288797782286941539983385173022")
    let result = bls12381.Fr.div(numerator, denominator)

    if (bls12381.Fr.toString(result) != '6895111531152973771500592584011752520924525831071581118085026095310658613421') {
        throw("division failed")
    }
    debugger
}

// proof consists of
// D - commitment
// sigma - ?
// y - ?
function checkKZGMultiProof(multiproof, bls12381) {
        let g2_of_t = bls12381.Fr.e("0")
        let power_of_r = bls12381.Fr.e("1")
        let E_coeffs = []

        debugger
        for (let i = 0; i < multiproof.indices.length; i++) {
            // E_coeff = r**i / (t - D[i])
            // why is (t - D[i]) not a modular arithmetic operation in dankrad's code?
            let E_coeff = bls12381.Fr.div(power_of_r, bls12381.Fr.sub(t, DOMAIN[i]))
            E_coeffs.append(E_coeff)

            g2_of_t += bls12381.Fr.mul(E_coeff, y)
            power_of_r = bls12381.Fr.mul(power_of_r, r)
        }

        // let E = bls12381.G1.multiExp(Cs, E_coeffs)
}

async function main() {
    bls12381 = await ffjavascript.buildBls12381(false)
    testG1Gen(bls12381)
    testG1GenDeserialize(bls12381)
    testFrDiv(bls12381)
    //checkKZGMultiProof(null, bls12381)
}

main()
