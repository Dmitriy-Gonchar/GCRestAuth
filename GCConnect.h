//
//  GCConnect.h
//
//  Created by Gonchar Dmitry on 02.03.2021.
//  Copyright © 2021 Gonchar Dmitry. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "BlockDeclare.h"
BlockTypeDecl(AuthBlock, void, NSString *_Nullable, NSError *_Nullable)
NS_ASSUME_NONNULL_BEGIN

@interface GCConnect : NSObject

@property NSString *auth_url;
@property NSString *email;
@property NSString *scope;
@property NSString *algorythm;
@property NSString *privateKey;
@property int lifetime; // in seconds

- (instancetype)initWithKey: (NSString *)key
					authURL: (NSString *)url
				  algorythm: (NSString *)alg
					  scope: (NSString *)scope
					  email: (NSString *)email;

- (void)getAuthTokenToBlock: (AuthBlock)block error: (NSError **)error;
@end

NS_ASSUME_NONNULL_END
