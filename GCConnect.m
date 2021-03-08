//
//  GCConnect.m
//
//  Created by Gonchar Dmitry on 02.03.2021.
//  Copyright © 2021 Gonchar Dmitry. All rights reserved.
//

#import "GCConnect.h"

#define PAYLOADFORMAT @"{\"iss\":\"%@\",\"scope\":\"%@\",\"aud\":\"%@\",\"exp\":%ld,\"iat\":%ld}"
#define HEADERFORMAT @"{\"alg\":\"%@\"}"
#define BODYFORMAT @"{\"grant_type\":\"urn:ietf:params:oauth:grant-type:jwt-bearer\",\"assertion\":\"%@\"}"
#define HTTPHEADER @{@"Content-Type": @"application/json", @"Accept": @"application/json"}
#define KEYLENGTH 1192
#define KEYSIZE @2048
#define ENC NSUTF8StringEncoding

@implementation GCConnect

- (instancetype)initWithKey: (NSString *)key
					authURL: (NSString *)url
				  algorythm: (NSString *)alg
					  scope: (NSString *)scope
					  email: (NSString *)email
{
	self = [super init];

	self.auth_url = url;
	self.email = email;
	self.scope = scope;
	self.algorythm = alg;
	self.lifetime = 3600;
	self.privateKey = key;

	return self;
}

- (void)getAuthTokenToBlock: (AuthBlock)block error: (NSError **)error
{
	NSString *header = [NSString stringWithFormat: HEADERFORMAT,
						 self.algorythm];
	NSString *payload = [NSString stringWithFormat: PAYLOADFORMAT,
						  self.email,
						  self.scope,
						  self.auth_url,
						  time(NULL) + self.lifetime,
						  time(NULL)];
	NSString *fullString = [self fulldataWithPayload: payload andHeader: header];
	NSData *fullData = [fullString dataUsingEncoding: ENC];
	SecKeyRef key = [self secKeyWithError: error];
	if (!key)
	{
		return;
	}
	NSString *signString = [self signatureData: fullData withKey: key error: error];
	NSString *signedRequestData = [@[fullString, signString] componentsJoinedByString: @"."];
	NSURL *authURL = [NSURL URLWithString: self.auth_url];
	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL: authURL];
	NSString *bodyString = [NSString stringWithFormat: BODYFORMAT, signedRequestData];
	NSData *body = [bodyString dataUsingEncoding: ENC];
	NSURLSession *session = NSURLSession.sharedSession;

	[request setHTTPBody: body];
	[request setAllHTTPHeaderFields: HTTPHEADER];
	[request setHTTPMethod: @"POST"];

	NSURLSessionDataTask *tsk = [session dataTaskWithRequest: request
										   completionHandler: ^(NSData *data,
																NSURLResponse *response,
																NSError *error)
	{
		if (error)
		{
			return block(nil, error);
		}

		NSError *jsonError = nil;
		NSDictionary *responseDict = [NSJSONSerialization JSONObjectWithData: data
																	 options: NSJSONReadingAllowFragments
																	   error: &jsonError];
		if (jsonError)
		{
			return block(nil, jsonError);
		}

		block(responseDict[@"access_token"], nil);
	}];

	[tsk resume];
}

- (NSString *)fulldataWithPayload: (NSString *)payload andHeader: (NSString *)header
{
	NSString *payloadString = urlencoded([[payload dataUsingEncoding: ENC] base64EncodedStringWithOptions: 0]);
	NSString *headerString = urlencoded([[header dataUsingEncoding: ENC] base64EncodedStringWithOptions: 0]);
	NSString *fullString = [@[headerString, @".", payloadString] componentsJoinedByString: @""];
	return fullString;
}

- (SecKeyRef)secKeyWithError: (NSError **)error
{
	NSString *secret = self.privateKey;
	NSArray <NSString *>* components = [secret componentsSeparatedByString: @"-----"];
	NSString *nonArmoredKey = secret;
	if (components.count > 2)
	{
		nonArmoredKey = components[2];
	}
	secret = [nonArmoredKey stringByReplacingOccurrencesOfString: @"\n" withString: @""];

	NSData *key = [NSData.alloc initWithBase64EncodedString: secret
													options: 0];

	NSDictionary *attributes = @{(NSString *)kSecAttrKeyType: (NSString *)kSecAttrKeyTypeRSA,
								 (NSString *)kSecAttrKeyClass: (NSString *)kSecAttrKeyClassPrivate,
								 (NSString *)kSecAttrKeySizeInBits: KEYSIZE};

	CFErrorRef cfError = nil;
	SecKeyRef secKey = nil;

	// brute force, instead of a thousand lines :В
	for (long chunkLength = KEYLENGTH; chunkLength--;)
	{
		for (long i = key.length - chunkLength; i >= 0; --i)
		{
			NSData *tempKey = [NSData dataWithBytes: &key.bytes[i]
											 length: chunkLength];
			secKey = SecKeyCreateWithData((CFDataRef)tempKey,
										  (CFDictionaryRef)attributes,
										  &cfError);
			if (secKey)
			{
				return secKey;
			}
		}
	}
	*error = (__bridge NSError *)cfError;
	return nil;
}

- (NSString *)signatureData: (NSData *)data withKey: (SecKeyRef)key error: (NSError **)error
{
	CFErrorRef cfError = nil;
	NSData *sign = CFBridgingRelease(SecKeyCreateSignature(key,
														   kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
														   (CFDataRef)data,
														   &cfError));
	if (cfError)
	{
		*error = (__bridge NSError *)cfError;
		return nil;
	}
	NSString *signString = urlencoded([sign base64EncodedStringWithOptions: 0]);
	return signString;
}

static NSString *urlencoded(NSString *string)
{
	return [[[string stringByReplacingOccurrencesOfString: @"+" withString: @"-"]
			 stringByReplacingOccurrencesOfString: @"/" withString: @"_"]
			stringByReplacingOccurrencesOfString: @"=" withString: @""];
}

@end
