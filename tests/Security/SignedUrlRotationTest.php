<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Security\SignedUrl;

it('preserves the signed URL v2 raw-secret wire format', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));

    expect($signedUrl->generate('https://example.com/download?file=report'))
        ->toBe('https://example.com/download?ep_v=2&file=report&ep_sig=dUI0YofIJvV67ydK3mBGE3QzsnTWulrLbQ5t4JHqHgE');
});

it('uses the active signed URL key for new writes and fallback keys for old verification', function () {
    $oldKey = str_repeat('o', 32);
    $newKey = str_repeat('n', 32);
    $oldSigner = new SignedUrl(new KeyRing([
        new KeyRingEntry('url-old', $oldKey, KeyStatus::ACTIVE, KeyPurpose::SIGNED_URL, 'sha256'),
    ]));
    $oldUrl = $oldSigner->generate('https://example.com/download', ['file' => 'report']);

    $rotatedSigner = new SignedUrl(new KeyRing([
        new KeyRingEntry('url-new', $newKey, KeyStatus::ACTIVE, KeyPurpose::SIGNED_URL, 'sha256'),
        new KeyRingEntry('url-old', $oldKey, KeyStatus::FALLBACK, KeyPurpose::SIGNED_URL, 'sha256'),
    ]));
    $oldResult = $rotatedSigner->verifyResult($oldUrl);
    $newUrl = $rotatedSigner->generate('https://example.com/download', ['file' => 'report']);
    $newResult = $rotatedSigner->verifyResult($newUrl);

    expect($oldUrl)->toContain('ep_kid=url-old')
        ->and($oldResult->verified)->toBeTrue()
        ->and($oldResult->matchedKeyId)->toBe('url-old')
        ->and($oldResult->usedFallbackKey)->toBeTrue()
        ->and($oldResult->keyNotUsable)->toBeFalse()
        ->and($newUrl)->toContain('ep_kid=url-new')
        ->and($newResult->verified)->toBeTrue()
        ->and($newResult->matchedKeyId)->toBe('url-new')
        ->and($newResult->usedFallbackKey)->toBeFalse();
});

it('authenticates the key selector and never tries unrelated keys', function () {
    $oldKey = str_repeat('o', 32);
    $newKey = str_repeat('n', 32);
    $signer = new SignedUrl(new KeyRing([
        new KeyRingEntry('url-new', $newKey, KeyStatus::ACTIVE, KeyPurpose::SIGNED_URL, 'sha256'),
        new KeyRingEntry('url-old', $oldKey, KeyStatus::FALLBACK, KeyPurpose::SIGNED_URL, 'sha256'),
    ]));
    $url = $signer->generate('https://example.com/download', ['file' => 'report']);

    $knownTamper = str_replace('ep_kid=url-new', 'ep_kid=url-old', $url);
    $knownResult = $signer->verifyResult($knownTamper);
    expect($knownResult->verified)->toBeFalse()
        ->and($knownResult->invalidSignature)->toBeTrue()
        ->and($knownResult->keyNotUsable)->toBeFalse()
        ->and($knownResult->matchedKeyId)->toBeNull();

    $unknownTamper = str_replace('ep_kid=url-new', 'ep_kid=url-missing', $url);
    $unknownResult = $signer->verifyResult($unknownTamper);
    expect($unknownResult->verified)->toBeFalse()
        ->and($unknownResult->invalidSignature)->toBeTrue()
        ->and($unknownResult->keyNotUsable)->toBeTrue()
        ->and($unknownResult->matchedKeyId)->toBeNull();

    $missingKid = str_replace('ep_kid=url-new&', '', $url);
    $missingResult = $signer->verifyResult($missingKid);
    expect($missingResult->verified)->toBeFalse()
        ->and($missingResult->keyNotUsable)->toBeTrue();
});

it('keeps signed URL keys isolated from signed payload keys', function () {
    $key = str_repeat('k', 32);
    $url = new SignedUrl(new KeyRing([
        new KeyRingEntry('shared-id', $key, KeyStatus::ACTIVE, KeyPurpose::SIGNED_URL, 'sha256'),
    ]))->generate('https://example.com/download');

    $wrongPurposeVerifier = new SignedUrl(new KeyRing([
        new KeyRingEntry('shared-id', $key, KeyStatus::ACTIVE, KeyPurpose::SIGNED_PAYLOAD, 'sha256'),
    ]));
    $result = $wrongPurposeVerifier->verifyResult($url);

    expect($result->verified)->toBeFalse()
        ->and($result->keyNotUsable)->toBeTrue();
});

it('reserves the signed URL key selector for Epicrypt rotation metadata', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));

    expect(fn () => $signedUrl->generate('https://example.com/download?ep_kid=caller'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $signedUrl->generate('https://example.com/download', ['ep_kid' => 'caller']))
        ->toThrow(ConfigurationException::class);
});
