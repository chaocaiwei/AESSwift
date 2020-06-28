//
//  State.swift
//  AESImpl
//
//  Created by myself on 2020/4/13.
//  Copyright © 2020 myself. All rights reserved.
//

import UIKit



func ^ (rh: Matrix,lh: Matrix) -> Matrix {
    return rh.xor(lh)
}


//class State : Matrix {
//    init(_ data: [UInt8]) {
//        var result = Array(repeating:Array(repeating:UInt8(0), count: 4), count: 4)
//        for i in 0..<4 {
//            for j in 0..<4 {
//                let index = 4 * i + j
//                result[j][i] = index < data.count ? data[index] : 0
//            }
//        }
//        super.init(content: result)
//    }
//}


struct  Matrix {
    
    var content: [[UInt8]]
    
    init(data: [UInt8]) {
        var result = Array(repeating:Array(repeating:UInt8(0), count: 4), count: 4)
        for i in 0..<4 {
            for j in 0..<4 {
                let index = 4 * i + j
                result[i][j] = index < data.count ? data[index] : 0
            }
        }
        self.content = result
    }
    
    init(content: [[UInt8]]) {
        self.content = content
    }
    
    func revert () -> Matrix {
        var content = self.content
        for (i,subArr) in content.enumerated() {
            for (j, _) in subArr.enumerated() {
                content[i][j] = content[j][i]
            }
        }
        return Matrix(content: content)
    }
    
    static var zero : Matrix {
        return Matrix(data: [UInt8](repeating: 0, count: 16))
    }
    
    
    init(words: [AESImpl.Word]) {
        let content =  words.reduce([]) { $0 + $1.content }
        self.init(data: content)
    }
    
    var data: [UInt8] {
        var result = Array(repeating: UInt8(0), count: 4 * 4)
        for i in 0..<4 {
            for j in 0..<4 {
                let index = 4 * i + j
                result[index] = content[i][j]
            }
        }
        return result
    }
    
    var words: [AESImpl.Word] {
        return self.content.map { AESImpl.Word($0) }
    }
    
    subscript (index: Int) -> [UInt8]{
        get {
            return self.content[index]
        }
        
        set(value){
            self.content[index] = value
        }
    }
    
    func xor (_ other: Matrix) -> Matrix {
        var content  = self.content
        for (i,subArr) in content.enumerated() {
            for (j,_) in subArr.enumerated() {
                content[i][j]  ^= other[i][j]
            }
        }
        return Matrix(content: content)
    }
    
   
}


extension Matrix : CustomStringConvertible {
    var description: String {
        var mstr = ""
        for i in 0..<4 {
            for j in 0..<4 {
                let data = self.content[j][i]
                mstr += String(format: "%2x ", data)
            }
            mstr += "\n"
        }
        return mstr
    }
}








