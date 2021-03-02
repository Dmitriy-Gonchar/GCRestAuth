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
#define ENC kCFStringEncodingUTF8

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
	NSString *plString = [NSString stringWithFormat: PAYLOADFORMAT,
						  self.email,
						  self.scope,
						  self.auth_url,
						  time(NULL) + self.lifetime,
						  time(NULL)];

	NSString *fullString = [self fulldataWithPayload: plString andHeader: header];
	NSData *fullData = [fullString dataUsingEncoding: ENC];
	SecKeyRef key = [self secKeyWithError: error];
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
													options: NSDataBase64DecodingIgnoreUnknownCharacters];

	if (key.length > KEYLENGTH)
	{
		key = [NSData dataWithBytes: &key.bytes[key.length - KEYLENGTH]
							 length: KEYLENGTH];
	}

	NSDictionary *attributes = @{(NSString *)kSecAttrKeyType: (NSString *)kSecAttrKeyTypeRSA,
								 (NSString *)kSecAttrKeyClass: (NSString *)kSecAttrKeyClassPrivate,
								 (NSString *)kSecAttrKeySizeInBits: KEYSIZE};
	CFErrorRef cfError = nil;
	SecKeyRef secKey = SecKeyCreateWithData((CFDataRef)key,
											(CFDictionaryRef)attributes,
											&cfError);
	if (cfError)
	{
		*error = (__bridge NSError *)cfError;
		return nil;
	}
	return secKey;
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
