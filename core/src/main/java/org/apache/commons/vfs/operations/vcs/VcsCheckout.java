/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.vfs.operations.vcs;

import org.apache.commons.vfs.operations.FileOperation;
import org.apache.commons.vfs.FileObject;

/**
 * todo: add class description here
 *
 * @author Siarhei Baidun
 * @since 0.1
 */
public interface VcsCheckout extends FileOperation
{
    /**
     *
     * @param revision
     */
    void setRevision(final long revision);

    /**
     *
     * @param recursive
     */
    void setRecursive(final boolean recursive);

    /**
     *
     * @param targetDir
     *            directory under which retrieved files should be placed.
     */
    void setTargetDirectory(final FileObject targetDir);

    /**
     * @param export
     *            if true, administrative .svn directoies will not be created on
     *            the retrieved tree. The checkout operation in this case is
     *            equivalent to export function.
     */
    void setExport(final boolean export);
}
