//
//  BlockDeclare.h
//
//  Created by Gonchar Dmitry on 11.12.2019.
//  Copyright © 2019 Gonchar Dmitry. All rights reserved.
//

#ifndef BlockDeclare_h
#define BlockDeclare_h

#define BlockTypeDecl(Type, RetType, /*ARGS*/...)\
typedef RetType (^Type)(__VA_ARGS__);


#endif /* BlockDeclare_h */
